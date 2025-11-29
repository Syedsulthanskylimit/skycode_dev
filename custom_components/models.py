# from form_generator.models import CreateProcess, Case, FormDataInfo, UserData
from django.db import models
import uuid
from django.utils import timezone
from django.contrib.auth.models import Permission
import pytz


def user_directory_path(instance, filename):
    return f'temp_files/{uuid.uuid4()}_{filename}'


class Bot(models.Model):
    """
    bot 0.1
    """
    BOT_CHOICES = [
        ('google_drive', 'google_drive'),
        ('email', 'email'),
        ('screen_scraping', 'screen_scraping'),
        ('file_extractor', 'file_extractor'),
        ('PDF Generator', 'PDF Generator'),
        ('Doc Builder', 'Doc Builder'),
        ('Doc Generator', 'Doc Generator'),
        ('Desktop Automation', 'Desktop Automation'),
        ('QR Generator', 'QR Generator'),
        ('Prompt Bot', 'Prompt Bot'),

    ]

    bot_uid = models.CharField(max_length=50, unique=True, blank=True, null=True, )
    name = models.CharField(max_length=50, null=True, blank=True)
    bot_name = models.CharField(max_length=100, choices=BOT_CHOICES, default='google_drive')
    bot_description = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"{self.bot_uid} - {self.bot_name}"
    
    class Meta:
        indexes = [
            models.Index(fields=['bot_uid']),
        ]


# Model to create organizations
class Organization(models.Model):
    objects = None
    org_name = models.CharField(max_length=100)
    org_code = models.CharField(max_length=5, unique=True)
    email = models.EmailField()
    org_description = models.TextField(blank=True, null=True)
    large_logo_url = models.URLField(blank=True, null=True)

    small_logo_url = models.URLField(blank=True, null=True)
    primary_color = models.CharField(max_length=10, blank=True, null=True)
    secondary_color = models.CharField(max_length=10, blank=True, null=True)
    accent1_color = models.CharField(max_length=10, blank=True, null=True)
    accent2_color = models.CharField(max_length=10, blank=True, null=True)
    accent3_color = models.CharField(max_length=10, blank=True, null=True)

    # form = models.ForeignKey('form_generator.FormDataInfo', on_delete=models.CASCADE, blank=True, null=True)
    bot = models.ForeignKey(Bot, on_delete=models.CASCADE, blank=True, null=True)
    admin_set_password = models.BooleanField(default=False)  # admin can set password for user

    # integration = models.ForeignKey(Integration, on_delete=models.CASCADE, blank=True, null=True)
    # dms = models.ForeignKey(Dms, on_delete=models.CASCADE, blank=True, null=True)
    # ocr = models.ForeignKey(Ocr, on_delete=models.CASCADE, blank=True, null=True)
    # dashboard = models.ForeignKey(Dashboard, on_delete=models.CASCADE, blank=True, null=True)
    # process = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, blank=True, null=True,
    #                             related_name='organization_process')

    # user_groups = models.ForeignKey(UserGroup, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.org_name


# Model to create user groups for the organizations
class UserGroup(models.Model):
    group_name = models.CharField(max_length=255)
    group_description = models.TextField()
    status = models.BooleanField(blank=True, null=True)
    # permissions = models.ManyToManyField(Permission, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='user_groups', blank=True,
                                     null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.group_name


class Dashboard(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    dashboard_types = models.CharField(max_length=100, blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='dashboard', blank=True,
                                     null=True)
    usergroup = models.ForeignKey(UserGroup, on_delete=models.CASCADE, related_name='usergroup_dashboard', blank=True,
                                  null=True)
    dashboard_config = models.JSONField(blank=True, null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    # status = models.BooleanField(blank=True, null=True)

    def __str__(self):
        return self.name


class BotSchema(models.Model):
    # bot = Bot(source='bot', read_only=True)
    """
    bot 0.2
    """
    bot = models.ForeignKey(Bot, on_delete=models.CASCADE, blank=True, null=True)
    bot_schema_json = models.JSONField(blank=True, null=True)
    bot_element_permission = models.JSONField(blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='bot_schema', blank=True,
                                     null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='process_bot_schema')

    def __str__(self):
        return f" Bot schema : {self.id}, {self.bot.bot_uid} - {self.bot.bot_name}"
    
    class Meta:
        indexes = [
            models.Index(fields=['bot']),
            models.Index(fields=['organization']),
            models.Index(fields=['flow_id']),
            models.Index(fields=['organization', 'bot']),
            models.Index(fields=['organization', 'flow_id']),
        ]


class BotData(models.Model):
    """
    bot 0.3
    """
    bot = models.ForeignKey(Bot, on_delete=models.CASCADE, blank=True, null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='bot_data')
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_bot_data')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='org_bot_data', blank=True,
                                     null=True)

    data_schema = models.JSONField(blank=True, null=True)
    temp_data = models.FileField(upload_to=user_directory_path, blank=True, null=True)

    file_name = models.CharField(max_length=255, null=True, blank=True)
    file_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)

    def __str__(self):
        return f"{self.id} - {self.bot}"


class Integration(models.Model):
    """
    Integration 0.1.1
    """
    INTEGRATION_CHOICES = [
        ('api', 'api'),
    ]

    Integration_uid = models.CharField(max_length=50, blank=True, null=True)
    integration_type = models.CharField(max_length=100, choices=INTEGRATION_CHOICES, default='api')
    integration_name = models.CharField(max_length=50, blank=True, null=True)
    description = models.CharField(max_length=50, blank=True, null=True)
    integration_schema = models.JSONField(blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='integration_schema',
                                     blank=True,
                                     null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='org_integration_schema')

    def __str__(self):
        return f"{self.id} - {self.integration_type}"


class IntegrationDetails(models.Model):
    """
    Integration 0.1.2
    """
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE, default=1)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, default=1,
                                related_name='integration_details')
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_integration_details')
    data_schema = models.JSONField(blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='org_integration_details',
                                     blank=True,
                                     null=True)

    def __str__(self):
        return str(self.id)


class Dms(models.Model):
    """
        Dms 0.1.1
    """
    CONFIG_TYPES = [
        ('Google Drive', 'Google Drive'),
        ('S3 Bucket', 'S3 Bucket'),
        ('One Drive', 'One Drive'),
        ('SFTP Storage', 'SFTP Storage'),
    ]
    dms_uid = models.CharField(max_length=50, blank=True, null=True)
    name = models.CharField(max_length=100, blank=True,
                            null=True)
    description = models.CharField(max_length=100, blank=True,
                                   null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     blank=True,
                                     null=True)

    drive_types = models.CharField(max_length=100, choices=CONFIG_TYPES, default='Google Drive')
    config_details_schema = models.JSONField(blank=True, null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, related_name='flow_dms', blank=True, null=True)
    # element_id_list = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} - {self.flow_id}"


class Dms_data(models.Model):
    filename = models.CharField(max_length=500, blank=True,
                                null=True)
    folder_id = models.CharField(max_length=500, blank=True,
                                 null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, related_name='dms_data',
                                blank=True,
                                null=True)  # 18-09-2025 by Harish [Product Level]
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_dms_data')  # 18-09-2025 by Harish [Product Level]
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='org_dms_data',
                                     blank=True,
                                     null=True)
    usergroup = models.ForeignKey(UserGroup, on_delete=models.CASCADE, related_name='usergroup_dms_data', blank=True,
                                  null=True)
    download_link = models.CharField(max_length=1000, blank=True,
                                     null=True)
    dms = models.ForeignKey(Dms, on_delete=models.CASCADE, related_name='dms_dms_data', blank=True,
                            null=True)
    field_id = models.CharField(max_length=500, blank=True, null=True)

    meta_data = models.JSONField(blank=True, null=True)
    user = models.ForeignKey('form_generator.UserData', on_delete=models.CASCADE, blank=True, null=True,
                             related_name='user_data')
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)

    def __str__(self):
        return str(self.id)


class Ocr(models.Model):
    """
        OCR 0.1.1
        """
    OCR_CHOICES = [
        ('Aadhar Card Extraction', 'Aadhar Card Extraction'),
        ('Pan Card Extraction', 'Pan Card Extraction'),
        ('PDF Extraction', 'PDF Extraction'),
        ('QR Extraction', 'QR Extraction'),
        ('Invoice Extraction', 'Invoice Extraction'),

    ]

    ocr_uid = models.CharField(max_length=50, blank=True, null=True)
    ocr_type = models.CharField(max_length=100, choices=OCR_CHOICES, default='Aadhar Card Extraction')
    name = models.CharField(max_length=100, blank=True, null=True)
    description = models.CharField(max_length=100, blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='ocr',
                                     blank=True,
                                     null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='process_ocr', blank=True,
                                null=True)

    def __str__(self):
        return str(self.id)


class Ocr_Details(models.Model):
    ocr_uid = models.CharField(max_length=50, blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='ocr_details',
                                     blank=True,
                                     null=True)
    data_schema = models.JSONField(blank=True, null=True)
    flow_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE, default=1,
                                related_name='process_ocr_details')
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_ocr_details')

    def __str__(self):
        return str(self.id)


# Model for Scheduler Table
class Scheduler(models.Model):
    SCHEDULER_CHOICES = (
        ('email spooling ', 'email spooling'),
        ('PDFSpooler', 'PDFSpooler'),
        # Add other processes here if needed
    )
    scheduler_uid = models.CharField(max_length=50, blank=True, null=True)

    scheduler_name = models.CharField(max_length=255, choices=SCHEDULER_CHOICES)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='scheduler',
                                     blank=True,
                                     null=True)
    process = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='process_scheduler',
                                blank=True,
                                null=True)
    frequency = models.CharField(max_length=100)  # e.g., "daily", "hourly", "every_5_minutes"
    scheduler_config = models.JSONField(blank=True, null=True)  # Storing the input JSON
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(default=timezone.now)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.scheduler_name} for {self.organization.org_name}"

    def schedule_next_run(self):
        current_time = timezone.now()

        # Set the appropriate timezone based on the time_zone field
        tz = pytz.timezone(self.time_zone)
        current_time = current_time.astimezone(tz)

        if self.frequency == "daily":
            self.next_run = current_time + timezone.timedelta(days=1)
        elif self.frequency == "hourly":
            self.next_run = current_time + timezone.timedelta(hours=1)
        elif self.frequency == "every_5_minutes":
            self.next_run = current_time + timezone.timedelta(minutes=5)
        # Add more scheduling logic as needed

        # Ensure next_run is timezone-aware
        self.next_run = tz.localize(self.next_run) if self.next_run else None
        self.save()

    # def schedule_next_run(self):
    #     if self.frequency == "daily":
    #         self.next_run = timezone.now() + timezone.timedelta(days=1)
    #     elif self.frequency == "hourly":
    #         self.next_run = timezone.now() + timezone.timedelta(hours=1)
    #     elif self.frequency == "every_5_minutes":
    #         self.next_run = timezone.now() + timezone.timedelta(minutes=5)
    #     # Add more scheduling logic as needed
    #     self.save()


class SchedulerData(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='schedulerdata',
                                     blank=True,
                                     null=True)
    process = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='process_schedulerdata',
                                blank=True,
                                null=True)
    filename = models.CharField(max_length=255, null=True, blank=True)
    data_json = models.JSONField(blank=True, null=True)  # Storing the input JSON
    status = models.CharField(max_length=255, null=True, blank=True)
    scheduler = models.ForeignKey(Scheduler, on_delete=models.CASCADE, related_name='scheduler',
                                  blank=True,
                                  null=True)
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_scheduler_data')

    def __str__(self):
        return f"{self.scheduler.scheduler_name} for {self.organization.org_name}"


################ Report Table Generation ####################################
class ReportConfig(models.Model):
    REPORT_TYPE_CHOICES = [
        ('process', 'Process'),
        ('form', 'Form'),
        ('subprocess', 'Subprocess'),
        ('core data', 'Core Data'),

    ]

    name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPE_CHOICES)
    data_id = models.PositiveIntegerField()  # ID of process, form, or case
    query = models.JSONField(blank=True, null=True)  # Store the query configuration in JSON format
    query_result = models.JSONField(blank=True, null=True)
    user_groups = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='ReportConfig',
                                     blank=True,
                                     null=True)
    chart_schema = models.JSONField(blank=True, null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.id} - {self.name} - {self.organization.org_name}"


################ Notification Configuration in Process ####################################
class NotificationBotSchema(models.Model):
    TYPE_CHOICES = [
        ("notify", "Notify"),
        ("approve", "Approve"),
    ]
    RECEIVER_TYPE_CHOICES = [
        ("field_ref", "Field Reference"),
        ("value", "Value"),
    ]

    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    notification_uid = models.CharField(max_length=255, blank=True, null=True)
    notification_name = models.CharField(max_length=255)
    notification_field_id = models.CharField(max_length=255)
    receiver_type = models.CharField(max_length=20, choices=RECEIVER_TYPE_CHOICES)
    receiver_mail = models.JSONField(blank=True, null=True)
    mail_content = models.JSONField(blank=True,
                                    null=True)  # If using Django < 3.1, use `from django.contrib.postgres.fields import JSONField`
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='notiifcationbot',
                                     blank=True,
                                     null=True)
    process = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='process_notificationbot',
                                blank=True,
                                null=True)
    notification_element_permission = models.JSONField(blank=True, null=True, default=list)

    def __str__(self):
        return f'{str(self.id)} - {self.notification_uid}'
        # return self.notification_name

    class Meta:
        indexes = [
            models.Index(fields=['notification_uid']),
        ]


class NotificationData(models.Model):
    mail_token_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # Generate ID
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, blank=True, null=True,
                                related_name='case_notification_data')
    mail_data = models.JSONField(blank=True, null=True)  # Save field values
    data_json = models.JSONField(blank=True, null=True)
    submitted = models.BooleanField(default=False)  # Submitted flag
    approved_id = models.CharField(max_length=255, blank=True, null=True)
    mail_title = models.CharField(max_length=255, blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='notiifcationdata',
                                     blank=True,
                                     null=True)
    process = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='process_notificationdata',
                                blank=True,
                                null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.mail_token_id)
        # return str(self.id)


class Agent(models.Model):
    TYPE_CHOICES = [
        ("Mail2PDF Agent", "Mail2PDF Agent"),
        # ("approve", "Approve"),
    ]

    agent_name = models.CharField(max_length=500,choices=TYPE_CHOICES)
    agent_description = models.TextField(blank=True, null=True)
    agent_config_schema = models.JSONField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    cron_timing = models.CharField(max_length=500, help_text="CRON expression like '0 0 * * *' for daily at midnight")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='agents', blank=True,
                                     null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.agent_name
