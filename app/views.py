from datetime import timedelta

from django.contrib.auth.password_validation import validate_password, get_password_validators
from django.dispatch import receiver
from django.utils import timezone
from django_rest_passwordreset.signals import reset_password_token_created, post_password_reset
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from app.serializers import UserSerializer, CustomeTokenObtainPairSerializer, ResetPasswordSerializer
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView
from django_rest_passwordreset.models import ResetPasswordToken, get_password_reset_token_expiry_time
from rest_framework.permissions import AllowAny
from Dummy import settings as s, settings
from rest_framework import exceptions
User = get_user_model()


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class LoginWithUserDetail(TokenObtainPairView):
    serializer_class = CustomeTokenObtainPairSerializer


class CustomPasswordResetView(GenericAPIView):
    permission_classes = [AllowAny]

    @receiver(reset_password_token_created)
    def password_reset_token_created(sender, reset_password_token, *args, **kwargs):
        from django.core.mail import EmailMultiAlternatives

        subject, from_email, to = 'Hi, {} Reset Your Password'.format(reset_password_token.user.username), \
            s.EMAIL_HOST_USER, reset_password_token.user.email
        text_content = 'This is an important message.'
        html_content = '<p>Use this token <strong>{}</strong> To Reset your Password \n</p>'.format(
            reset_password_token.key)
        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_content, "text/html")
        msg.send()


class ConfirmPasswordView(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        password2 = serializer.validated_data['password2']
        token = serializer.validated_data['token']

        password_reset_token_validation_time = get_password_reset_token_expiry_time()
        # find token
        reset_password_token = ResetPasswordToken.objects.filter(key=token).first()
        if reset_password_token is None:
            return Response({'status': 'Token not found.'}, status=status.HTTP_404_NOT_FOUND)
        # check expiry date
        expiry_date = reset_password_token.created_at + timedelta(hours=password_reset_token_validation_time)
        if timezone.now() > expiry_date:
            # delete expired token
            reset_password_token.delete()
            return Response({'status': 'Token expired'}, status=status.HTTP_404_NOT_FOUND)

        # get password validation
        if password != password2:
            return Response({'status': 'Password mismatch'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # validate the password against existing validators
            validate_password(
                password,
                user=reset_password_token.user,
                password_validators=get_password_validators(settings.AUTH_PASSWORD_VALIDATORS)
            )
        except exceptions.ValidationError as e:
            # raise a validation error for the serializer
            raise exceptions.ValidationError({
                'password': e
            })

        reset_password_token.user.set_password(password)
        reset_password_token.user.save()
        post_password_reset.send(sender=self.__class__, user=reset_password_token.user)

        # Delete all password reset tokens for this user
        ResetPasswordToken.objects.filter(user=reset_password_token.user).delete()

        return Response({'status': 'Password reset successfully'})
