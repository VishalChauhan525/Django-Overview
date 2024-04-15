from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import exceptions, filters
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import permission_classes
from api.serializers import UserSerializer
from django.views.generic import DeleteView
from django.conf import settings
import math
import json
from api.utils import (
    generate_access_token,
    createinstamojotoken,
    deleteUserCourse,
    generate_refresh_token,
    checkAndGenerateAccessToken,
    sendEmail,
    getResetPasswordEmailTemplate,
    uploadPublicFile,
    getEnquiryTemplateForOwner,
    getGeneralEnquiryTemplateForOwner,
    getGeneralEnquiryTemplateForVisiter,
    getUserInfoEnquiryTemplateForVisiter,
    getUserInfoEnquiryTemplateForOwner,
    getEnquiryTemplateForVisiter,
    uploadPrivateFile,
    getPrivateFileUrl,
    getSubscriptionEmailForUserTemplate,
    getSubscriptionEmailForAdminTemplate,
    createinstamojotoken,
    downloadFile,
    deleteFile,
    getConfirmEmailTemplate,
    # sendWhatsAppNotification
)
from api.models import *
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.decorators import parser_classes
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
import io
from datetime import datetime
from .mypaginationclass import MyLimitOffsetPagination, PageNumberPagination
from rest_framework.generics import (
    ListAPIView,
    DestroyAPIView,
    RetrieveUpdateDestroyAPIView,
)
from django_filters.rest_framework import DjangoFilterBackend
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta, timezone
import pandas as pd
from django.core.files.storage import FileSystemStorage
import os
import requests
import boto3

# region Anonymous
# region Internal Use Functions
# Insert User Login History
def logUserLoginHistory(userid, successfulLogin):
    userLoginSerializer = CreateUserLoginsSerializer(
        data={"userId": userid, "successfulLogin": successfulLogin}
    )
    if userLoginSerializer.is_valid():
        userLoginSerializer.save()


# Updates User Last Login
def updatelastlogin(user):
    user.last_login = datetime.now()
    user.save(update_fields=["last_login"])


# Return Result with column name with the raw query
def dictfetchall(cursor):
    "Return all rows from a cursor as a dict"
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# Save Email Verification Link
def SaveEmailVerification(token, userId):
    expiryDate = datetime.now()
    expiryDate = expiryDate + timedelta(hours=24)
    userEmailVerficationSerializer = CreateEmailVerificationSerializer(
        data={
            "id": generateGUId(),
            "token": token,
            "isExpired": False,
            "expiryDate": expiryDate,
            "userId": userId,
        }
    )
    if userEmailVerficationSerializer.is_valid():
        userEmailVerficationSerializer.save()


# endregion


# Generates fresh asscess token using refresh token


class generateAccessTokenView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser]

    # Form-Data Keys Values : refreshToken
    def get(self, request, pk=None, format=None) -> Response:
        return Response(
            checkAndGenerateAccessToken(request.GET["refreshToken"]),
            status=status.HTTP_200_OK,
        )


# Resets User Password


class resetUserPasswordView(APIView):
    permission_classes = [AllowAny]

    # Form-Data Keys : userId,password
    def post(self, request, pk=None, format=None) -> Response:
        user = User.objects.get(id=request.data.get("userId"))
        user.set_password(request.data.get("password"))
        serializer = UserSerializer(user, data=user.__dict__)
        if serializer.is_valid():
            serializer.save()
            dict = {"userId": request.data.get("userId")}
            passwordHistorySerializer = CreateUpdatePasswordHistorySerializer(data=dict)
            if passwordHistorySerializer.is_valid():
                passwordHistorySerializer.save()
            else:
                print(passwordHistorySerializer.errors)
            return Response("Password Updated Successfully", status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# endregion


# region Admin User Related Methods

# User Registration


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser]

    # Form-Data Keys : title,first_name,last_name,stateId,city,phoneNumber,email,password
    def post(self, request, pk=None, format=None) -> Response:
        serializer = RegistrationSerializers(data=request.data)
        data = {}
        if serializer.is_valid():
            user = serializer.save()
            return Response("Successfully register", status=status.HTTP_200_OK)

        else:
            return Response(
                serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# User Login


class UserLoginView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser]

    # Form-Data Keys : email,password
    def post(self, request, pk=None, format=None) -> Response:
        User = get_user_model()
        email = request.data.get("email")
        password = request.data.get("password")
        response = Response()
        user = User.objects.filter(email=email).first()
        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Emailid or Password")
        if user.emailConfirmed == False:
            return Response("Email not confirmed", status.HTTP_401_UNAUTHORIZED)
        if user.is_active == False:
            return Response("User not active", status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            logUserLoginHistory(user.id, False)
            raise exceptions.AuthenticationFailed("Invalid Emailid or Password")
        serialized_user = UserSerializer(user).data
        access_token = generate_access_token(user.id)
        refresh_token = generate_refresh_token(user)
        logUserLoginHistory(user.id, True)
        updatelastlogin(user)
        response.data = {
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "user": serialized_user,
        }
        response.serialize_headers
        return response


# Records User Logins


class CreateUserLoginsApiView(APIView, PageNumberPagination):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser]

    # Form-Data Keys : userId,successfulLogin
    def post(self, request, pk=None, format=None) -> Response:
        serializer = CreateUserLoginsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            data = serializer.errors
            return Response(data)


# Generate reset Password link


class SendResetpasswordLink(APIView):
    permission_classes = [AllowAny]

    # Form-Data Keys : email
    def post(self, request, pk=None, format=None) -> Response:
        try:
            email = request.data.get("email")
            user = User.objects.filter(email=email).first()
            print(user)
            if user is not None:
                print("inside if")
                # do something
                message = getResetPasswordEmailTemplate(
                    settings.FRONTEND_URL + "/resetpassword?id=" + user.id
                )
                sendEmail([user.email], "Email Verification", message)
                return Response("Email Sent", status.HTTP_200_OK)
            else:
                print("else condition")
                return Response("Email Not Found", status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)


#  Verify Signup Token


class VerifySignupToken(APIView):
    permission_classes = [AllowAny]

    # Form-Data Keys : signUpToken,userId
    def post(self, request, pk=None, format=None) -> Response:
        signUpToken = request.data.get("signUpToken")
        userId = request.data.get("userId")

        # check token value is not blank
        if signUpToken == "":
            return Response(
                "Please Provide Signup Token", status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # get token detail
        tokenDetail = EmailVerification.objects.filter(
            token=signUpToken, userId=userId
        ).first()

        # get user detail
        user = User.objects.filter(id=userId).first()

        # check user is not null
        if user is not None:
            if user.emailConfirmed:
                return Response("Email already verified", status.HTTP_409_CONFLICT)

            # check token detail is not null
            if tokenDetail is not None:
                expiryDate = tokenDetail.expiryDate
                currentDate = datetime.now(timezone.utc)

                # check  token is not expired
                if currentDate <= expiryDate:
                    print("Token Not Expired")
                    user.emailConfirmed = True
                    user.is_active = True
                    serializer = UserSerializer(user, data=user.__dict__)
                    if serializer.is_valid():
                        serializer.save()
                    else:
                        return Response(
                            "Internal error", status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                    return Response("Email Verified Successfully", status.HTTP_200_OK)
                else:
                    eamilSerializer = CreateEmailVerificationSerializer(
                        tokenDetail, data={"isExpired": True}, partial=True
                    )
                    if eamilSerializer.is_valid():
                        eamilSerializer.save()
                    else:
                        return Response(
                            "Internal error", status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                    print("Token Expird")
                    return Response("Signup token expired", status.HTTP_400_BAD_REQUEST)
            else:
                return Response("Token not found", status.HTTP_404_NOT_FOUND)
        else:
            return Response("User not found", status.HTTP_404_NOT_FOUND)


# resend email Verification


class ResendEmailVerificationLink(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser]

    # Form-Data Keys : email
    def post(self, request, pk=None, format=None) -> Response:
        user = User.objects.filter(email=request.data["email"]).first()
        if not user:
            return Response("User does not exist", status.HTTP_400_BAD_REQUEST)

        if user.emailConfirmed:
            return Response("Email is already verified", status.HTTP_400_BAD_REQUEST)

        resendEmailVerificationMessage = getConfirmEmailTemplate(
            settings.FRONTEND_URL
            + "/verifyemail?token="
            + user.signUpToken
            + "&userId="
            + user.id
        )
        emailVerificationTokens = EmailVerification.objects.filter(
            userId=user.id, isExpired=False
        )
        for token in emailVerificationTokens:
            # tokenValue = token
            # token.isExpired = True
            # token.expiryDate = datetime.now()
            # serializer = EmailVerification(tokenValue, token)
            serializer = CreateEmailVerificationSerializer(
                token,
                data={"isExpired": True, "expiryDate": datetime.now()},
                partial=True,
            )
            if serializer.is_valid():
                serializer.save()
        sendEmail([user.email], "Email Verification", resendEmailVerificationMessage)
        SaveEmailVerification(user.signUpToken, user.id)
        return Response("Email Sent Successfully", status.HTTP_200_OK)


# Returns All User Logins
class AllUserLogingsView(ListAPIView):
    # http://127.0.0.1:8000/api/AllUserHistoryList?userId__username=VishalChauhan666
    # http://127.0.0.1:8000/api/AllUserHistoryList?search=VishalChauhan666
    # http://127.0.0.1:8000/api/AllUserHistoryList?ordering=userId__username

    permission_classes = [IsAuthenticated]
    queryset = UserLogins.objects.all()
    serializer_class = UserLoginListSerializer
    pagination_class = PageNumberPagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["id", "userId", "successfulLogin", "userId__username"]
    search_fields = ["userId__id", "successfulLogin", "userId__username"]
    ordering_fields = ["userId__id", "successfulLogin", "userId__username"]


