from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    admin = models.BooleanField(default=False)
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(max_length=15, unique=True)
    USERNAME_FIELD = "mobile_number"  # or email or by default it takes username

    def __str__(self):
        return self.username
