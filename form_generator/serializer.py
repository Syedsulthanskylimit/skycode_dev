"""
author : mohan
app_name : form_generator
"""
from rest_framework import serializers
from .models import *
import json
from django import forms
from .models import FormPermission

from rest_framework import serializers
from django.contrib.auth.models import User


# To convert Json field from string to dict in serializer for API to accept the data in json format

class JSONField(serializers.Field):
    def to_internal_value(self, data):
        # Convert JSON data to Python dictionary
        if isinstance(data, str):
            return json.loads(data)
        return data

    def to_representation(self, value):
        # Convert Python dictionary to JSON data
        if isinstance(value, dict):
            return value
        return json.dumps(value)


class FormDataInfoSerializer(serializers.ModelSerializer):
    # form_json_schema = JSONField()
    form_json_schema = serializers.ListField(child=serializers.DictField())
    form_style_schema = serializers.ListField(child=serializers.DictField())
    form_filter_schema = JSONField(default=list)
    # form_send_mail_schema = jsonfield.JSONField(blank=True)
    form_rule_schema  = JSONField(default=list)
    class Meta:
        model = FormDataInfo
        fields = '__all__'
        extra_kwargs = {
            'processId': {'required': False, 'allow_null': True},
            'organization': {'required': False, 'allow_null': True},
        }
class FormDataInfoMinimalSerializer(serializers.ModelSerializer):
    class Meta:
        model = FormDataInfo
        fields = ['id', 'form_name', 'form_description', 'processId_id', 'permissions']

class FilledDataInfoSerializer(serializers.ModelSerializer):
    data_json = JSONField()
    created_on = serializers.DateTimeField(source='caseId.created_on', read_only=True)
    updated_on = serializers.DateTimeField(source='caseId.updated_on', read_only=True)
    process_name = serializers.CharField(source='processId.process_name', read_only=True)
    user_groups = serializers.SerializerMethodField()
    # user_groups = serializers.IntegerField(source='user_groups.id', read_only=True)
    """
    filled  data serializer
    """

    class Meta:
        """
        Metaclass is used to define metadata options for the model.
        """
        model = FilledFormData
        fields = '__all__'

    def get_user_groups(self, obj):
        return obj.user_groups.values_list('id', flat=True)


class FormPermissionForm(forms.ModelForm):
    class Meta:
        model = FormPermission
        fields = ['user_group', 'form', 'read', 'write', 'edit']


class UserLoginSerializer(serializers.Serializer):
    username = serializers.EmailField()
    password = serializers.CharField(write_only=True, required=True, min_length=8)


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)

    def validate_password(self, value):
        # Add any additional password validations here
        return value


# class UserInfoSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserData
#         fields = '__all__'
#
#     def create(self, validated_data):
#         user = User.objects.create_user(
#             username=validated_data['username'],
#             email=validated_data['email'],
#             password=validated_data['password']
#         )
#         # Set the role if you have a role field or separate model
#         # user.role = validated_data.get('role', None)
#         # user.save()
#         return user

class UserDataSerializer(serializers.ModelSerializer):
    user_profile_schema = serializers.JSONField()
    class Meta:
        model = UserData
        fields = ['id', 'user_name', 'mail_id', 'password', 'organization', 'usergroup', 'profile_pic', 'is_lead','user_profile_schema', 'uid']
class UserDataListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list/search APIs"""
    # user_profile_schema = serializers.JSONField()
    class Meta:
        model = UserData
        exclude = ('user_profile_schema',)


class NotificationConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationConfig
        fields = '__all__'


# adding this for process and case management :
class CreateProcessSerializer(serializers.ModelSerializer):
    participants = JSONField()

    class Meta:
        """
        process create
        Metaclass is used to define metadata options for the model.
        """

        model = CreateProcess
        fields = ['id', 'process_name', 'participants', 'process_description', 'organization', 'user_group', 'uid']
        # fields = '__all__'


class CreateProcessResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreateProcess
        fields = ['id', 'process_name', 'process_description', 'user_group','parent_process']


class CaseSerializer(serializers.ModelSerializer):
    assigned_users = serializers.PrimaryKeyRelatedField(
        many=True, queryset=UserData.objects.all()
    )  # Allows multiple users to be assigned
    parent_case_data = serializers.JSONField(required=False, allow_null=True)
    process_name = serializers.CharField(source='processId.process_name', read_only=True)

    # user_case_history = serializers.ListField(
    #     child=serializers.DictField(),  # Ensure it accepts a list of dictionaries
    #     required=False,  # Allow empty lists
    #     default=list  # Default to an empty list
    # )

    class Meta:
        """
        Case management
        Metaclass is used to define metadata options for the model.
        """
        model = Case
        fields = '__all__'

class ProcessCaseListSerializer(serializers.ModelSerializer):
    assigned_users = serializers.PrimaryKeyRelatedField(
        many=True, queryset=UserData.objects.all()
    )  # Allows multiple users to be assigned
    assigned_users_data = serializers.SerializerMethodField()
    parent_case_data = serializers.JSONField(required=False, allow_null=True)
    class Meta:
        """
        Case management
        Metaclass is used to define metadata options for the model.
        """
        model = Case
        fields = [
                    "id",
                    "assigned_users",
                    "assigned_users_data",
                "created_by",
                    "created_on",
                    "organization",
                    "parent_case_data",
                    "status",
                    "stages",
                    "updated_by",
                    "updated_on",
                    "next_step",
                    "user_case_history",
                    "processId",
                    "parent_case",
                ]

    def get_assigned_users_data(self, obj):
            try:
                user_ids = list(obj.assigned_users.values_list("id", flat=True))  # if ManyToMany
            except AttributeError:
                # If assigned_users is stored as a list in JSON
                user_ids = obj.assigned_users if isinstance(obj.assigned_users, list) else []

            users = UserData.objects.filter(id__in=user_ids)
            return [
                {
                    "id": user.id,
                    "name": user.user_name,
                    "profile_pic": user.profile_pic or None,
                    "mail_id":user.mail_id
                }
                for user in users
            ]



class RuleSerializer(serializers.ModelSerializer):
    rule_json_schema = JSONField()

    class Meta:
        """
        Rule management
        """
        model = Rule
        fields = '__all__'


class SlaSerializer(serializers.ModelSerializer):
    class Meta:
        """
        Rule management
        """
        model = Sla
        fields = '__all__'


class CoreDataInfoSerializer(serializers.ModelSerializer):
    """
    Core Data Table
    """
    form_json_schema = serializers.ListField(child=serializers.DictField())
    form_style_schema = serializers.ListField(child=serializers.DictField())
    class Meta:
        model = FormDataInfo
        fields = '__all__'  # Include all fields or specify the required fields


class SequenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sequence
        fields = '__all__'



class UserFormSchemaSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFormSchema
        fields = '__all__'
class CaseDashboardSerializer(serializers.ModelSerializer):
    assigned_users = serializers.PrimaryKeyRelatedField(
        many=True, queryset=UserData.objects.all()
    )  # Allows multiple users to be assigned
    parent_case_data = serializers.JSONField(required=False, allow_null=True)
    process_name = serializers.CharField(source='processId.process_name', read_only=True)

    # user_case_history = serializers.ListField(
    #     child=serializers.DictField(),  # Ensure it accepts a list of dictionaries
    #     required=False,  # Allow empty lists
    #     default=list  # Default to an empty list
    # )

    class Meta:
        """
        Case management
        Metaclass is used to define metadata options for the model.
        """
        model = Case
        exclude = ['user_case_history','path_json','case_data_comments','current_subprocess']
        # fields = '__all__'
