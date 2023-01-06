from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'password', 'last_login', 'is_superuser', 'username', 'first_name', 'last_name', 'is_staff',
                  'is_active', 'date_joined', 'admin', 'email', 'mobile_number', 'groups', 'user_permissions']
        read_only_fields = ['id', 'last_login', 'is_superuser', 'first_name', 'last_name', 'is_staff', 'is_active',
                            'date_joined', 'admin', 'mobile_number', 'groups', 'user_permissions']

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return User.objects.create(**validated_data)


class CustomeTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super(CustomeTokenObtainPairSerializer, self).validate(attrs)
        if self.user.is_active is not True:
            raise serializers.ValidationError({"message": "User is not active."})
        data.update({
            'username': self.user.username,
            'email': self.user.email,
            'mobile_number': self.user.mobile_number
        })
        return data


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'})
    password2 = serializers.CharField(style={'input_type': 'password'})
    token = serializers.CharField()