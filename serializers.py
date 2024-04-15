from rest_framework import serializers
from api.models import *
from api.utils import generateGUId
from api.models import UserHistory, UserLogins

# from utils import sendEmail


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "phoneNumber",
            "first_name",
            "last_name",
            "is_active",
            "last_login",
            "phoneNumber",
        ]


class UserDetailSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={"input_type": "password"}, write_only=True)
    passwordHash = serializers.CharField(write_only=True)
    securityStamp = serializers.CharField(write_only=True)
    emailConfirmed = serializers.CharField(write_only=True)
    is_staff = serializers.CharField(write_only=True)
    is_superuser = serializers.CharField(write_only=True)
    is_staff = serializers.CharField(write_only=True)
    signUpToken = serializers.CharField(write_only=True)
    twoFactorEnabled = serializers.CharField(write_only=True)
    lockoutEndDateUtc = serializers.CharField(write_only=True)
    lockoutEnabled = serializers.CharField(write_only=True)
    accessFailedCount = serializers.CharField(write_only=True)
    last_updated_on = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = "__all__"


class UserEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email"]


class PropertyListSerializer(serializers.ModelSerializer):
    propertyType = serializers.CharField(source="propertyTypeId.name")
    category = serializers.CharField(source="categoryId.name")
    brochureUrl = serializers.SerializerMethodField()
    titleClearanceCertificateUrl = serializers.SerializerMethodField()
    selfOwnershipUrl = serializers.SerializerMethodField()
    selfOwnershipName = serializers.SerializerMethodField()
    titleClearanceCertificateName = serializers.SerializerMethodField()
    brochureName = serializers.SerializerMethodField()
    layoutApprovalName = serializers.SerializerMethodField()
    licenceApprovalsTakenName = serializers.SerializerMethodField()
    buildingPlanApprovalName = serializers.SerializerMethodField()
    summaryName = serializers.SerializerMethodField()
    layoutApprovalUrl = serializers.SerializerMethodField()
    buildingPlanApprovalUrl = serializers.SerializerMethodField()
    summaryUrl = serializers.SerializerMethodField()
    licenceApprovalsTakenUrl = serializers.SerializerMethodField()
    def get_brochureName(self, property):
        if hasattr(property, "projectBrochureUpload"):
            brochure = property.projectBrochureUpload
            if brochure and hasattr(brochure, 'orignalDocumentName'):
                return brochure.orignalDocumentName
            else:
                return None
        else:
            return None
    def get_licenceApprovalsTakenName(self, property):
        if hasattr(property, "licenceApprovalsTaken"):
            brochure = property.licenceApprovalsTaken
            if brochure and hasattr(brochure, 'orignalDocumentName'):
                return brochure.orignalDocumentName
            else:
                return None
        else:
            return None
    def get_summaryName(self, property):
        if hasattr(property, "Summary"):
            brochure = property.Summary
            if brochure and hasattr(brochure, 'orignalDocumentName'):
                return brochure.orignalDocumentName
            else:
                return None
        else:
            return None
    def get_layoutApprovalName(self, property):
        if hasattr(property, "layoutApproval"):
            brochure = property.layoutApproval
            if brochure and hasattr(brochure, 'orignalDocumentName'):
                return brochure.orignalDocumentName
            else:
                return None
        else:
            return None
    def get_buildingPlanApprovalName(self, property):
        if hasattr(property, "buildingPlanApproval"):
            brochure = property.buildingPlanApproval
            if brochure and hasattr(brochure, 'orignalDocumentName'):
                return brochure.orignalDocumentName
            else:
                return None
        else:
            return None