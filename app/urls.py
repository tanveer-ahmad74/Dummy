from django.urls import path, include
from rest_framework.routers import DefaultRouter

from app.views import UserViewSet, LoginWithUserDetail, ConfirmPasswordView

router_master = DefaultRouter()
router_master.register('user', UserViewSet, basename='user')


urlpatterns = [
    path('', include(router_master.urls)),
    path('login/', LoginWithUserDetail.as_view(), name='token_obtain_pair'),   # login api
    path('confirm_password/', ConfirmPasswordView.as_view(), name='confirm_password'),  # confirm password
    path('password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),  # password_reset
]