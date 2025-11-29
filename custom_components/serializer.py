from venv import logger

from rest_framework import serializers

from form_generator.models import CreateProcess
from .models import Bot, BotSchema, BotData, Integration, IntegrationDetails, Organization, UserGroup, Ocr, Ocr_Details, \
    Dashboard, \
    Dms, Dms_data, Ocr_Details, Scheduler, SchedulerData, ReportConfig, NotificationBotSchema, NotificationData, Agent
import json
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType


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


class BotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bot
        fields = ['name', 'bot_name', 'bot_description', 'bot_uid']


class BotSchemaSerializer(serializers.ModelSerializer):
    bot = serializers.PrimaryKeyRelatedField(queryset=Bot.objects.all())
    # bot = BotSerializer()
    # bot = BotSerializer(read_only=True)
    bot_schema_json = JSONField()
    bot_element_permission = serializers.JSONField(required=False, allow_null=True)
    flow_id = serializers.PrimaryKeyRelatedField(queryset=CreateProcess.objects.all(), allow_null=True,
                                                 required=False)  # Add this line

    class Meta:
        model = BotSchema
        # fields = ['bot', 'bot_schema_json']
        # fields = '__all__'
        fields = ['id', 'bot_schema_json', 'flow_id', 'organization', 'bot', 'bot_element_permission']


class BotDataSerializer(serializers.ModelSerializer):
    data_schema = JSONField()
    bot_name = serializers.CharField(source='bot.bot_name',
                                     read_only=True)  # Include bot_name from the related Bot model

    class Meta:
        model = BotData
        fields = '__all__'


class IntegrationSerializer(serializers.ModelSerializer):
    integration_schema = JSONField()

    class Meta:
        model = Integration
        fields = '__all__'


class IntegrationDetailsSerializer(serializers.ModelSerializer):
    data_schema = JSONField()
    integration_type = serializers.CharField(source='integration.integration_type',
                                             read_only=True)  # Include bot_name from the related Bot model

    class Meta:
        model = IntegrationDetails
        fields = '__all__'


class OcrSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ocr
        fields = ['id', 'ocr_uid', 'ocr_type', 'name', 'description', 'organization']


class Ocr_DetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ocr_Details
        fields = '__all__'


class DashboardConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dashboard
        fields = '__all__'


class DashboardSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='usergroup.group_name', read_only=True)
    dashboard_config = JSONField()

    class Meta:
        model = Dashboard
        fields = '__all__'

    def create(self, validated_data):
        usergroup = validated_data.get('usergroup')
        if Dashboard.objects.filter(usergroup=usergroup).exists():
            logger.error(f"Usergroup {usergroup.group_name} already has an assigned dashboard.")
            raise serializers.ValidationError("This usergroup already has an assigned dashboard.")

        # return data
        # Call the parent class's create method to actually create the object
        return super().create(validated_data)


# class PermissionSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Permission
#         fields = ['id', 'codename', 'name', 'content_type']
class CustomPermissionSerializer(serializers.Serializer):
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    delete = serializers.BooleanField()


# serializer to validate the incoming password
class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True, min_length=8)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class UserGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroup
        fields = ['id', 'group_name', 'group_description', 'status', 'organization', 'uid']


class OrganizationSerializer(serializers.ModelSerializer):
    user_groups = UserGroupSerializer(many=True, read_only=True)

    class Meta:
        model = Organization
        fields = '__all__'

    def validate_code(self, value):
        if Organization.objects.filter(code=value).exists():
            raise serializers.ValidationError(f"The code '{value}' is already in use.")
        return value


class DmsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dms
        fields = '__all__'


class DmsDataSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()

    class Meta:
        model = Dms_data
        fields = '__all__'

    def get_username(self, obj):
        try:
            if obj.user:  # check if user FK exists
                return obj.user.user_name
        except Exception as e:
            print("Error getting username:", e)
        return None


class SchedulerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scheduler
        fields = ['scheduler_uid', 'scheduler_name', 'organization', 'process', 'frequency', 'scheduler_config']

    def create(self, validated_data):
        return Scheduler.objects.create(**validated_data)


class SchedulerDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchedulerData
        fields = '__all__'


############ Serializer for Report Table ############################

class ReportConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportConfig
        fields = ['id', 'name', 'report_type', 'user_groups', 'data_id', 'query_result', 'query', 'query_result',
                  'organization', 'chart_schema', 'created_at', 'updated_at', 'uid']


from rest_framework import serializers


class ScriptExecutionSerializer(serializers.Serializer):
    variablesList = serializers.ListField(child=serializers.DictField())
    filledData = serializers.DictField()
    encodedScript = serializers.CharField()


class NotificationBotSchemaSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationBotSchema
        fields = '__all__'

    def validate_receiver_mail(self, value):
        if isinstance(value, str):
            return value
        elif isinstance(value, list) and all(isinstance(email, str) for email in value):
            return value
        raise serializers.ValidationError("receiver_mail must be a string or list of strings.")


class NotificationDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationData
        fields = '__all__'


class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = '__all__'
