"""
author : mohan
app_name : form_generator
"""
from django.contrib.auth.models import User
from django.db import models
from datetime import date
from django.contrib.postgres.indexes import GinIndex

# from custom_components.models import Organization


# adding this for process and case management TWS:
class CreateProcess(models.Model):
    """
    create process
    """
    # process_id = models.CharField(max_length=200,blank=True,null=True)
    process_name = models.CharField(max_length=200, blank=True)
    process_description = models.CharField(max_length=700, blank=True, null=True)
    initiator_group = models.IntegerField(null=True, blank=True)
    # prefix = models.CharField(max_length=255, blank=True)
    first_step = models.CharField(max_length=255, blank=True, null=True)
    participants = models.JSONField(blank=True, null=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='create_process', blank=True, null=True)
    user_group = models.ManyToManyField('custom_components.UserGroup',
                                        related_name='usergroup_create_process', blank=True)
    dms = models.ManyToManyField('custom_components.DMS',
                                 related_name='dms', blank=True)  # added dms to tag the process
    parent_process = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE,
                                       related_name='subprocesses')
    subprocess_UID = models.CharField(max_length=50, blank=True)
    process_stages = models.JSONField(blank=True, null=True)  # added on 14.3.25 to include Process Stages
    process_table_configuration = models.JSONField(blank=True, null=True) # added on 31.3.25 to include table config
    parent_case_data_schema = models.JSONField(blank=True, default=list, null=True)
    process_table_permission = models.JSONField(blank=True, default=list, null=True) #### for table permission updated on 4.6.25
    uid = models.CharField(max_length=50, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, null=True, blank=True)
    
    # 08-10-2025 by Harish (Indexing for enhancement)[Project TI]
    class Meta:
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['subprocess_UID']),
            models.Index(fields=['organization', 'subprocess_UID']),
        ]

    def __str__(self):
        return f"Process: {self.process_name} (ID: {self.id}), Organization: {self.organization.org_name}"
        # return str(self.id)


# adding this for process and case management TWS:
class Case(models.Model):
    """
    case management
    """
    processId = models.ForeignKey(CreateProcess, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    created_by = models.CharField(max_length=300, blank=True)
    status = models.CharField(max_length=500)
    stages = models.CharField(max_length=500,blank=True)
    updated_on = models.DateTimeField(auto_now=True, null=True, blank=True)
    updated_by = models.CharField(max_length=300, blank=True)
    next_step = models.CharField(max_length=200, blank=True) 
    data_json = models.JSONField(blank=True, null=True)
    path_json = models.JSONField(blank=True, default=list, null=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='case', blank=True, null=True)
    # parent_caseId = models.CharField(max_length=500,blank=True, null=True)
    parent_case = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='sub_cases')
    current_subprocess = models.ForeignKey(CreateProcess, null=True, blank=True,
                                           on_delete=models.SET_NULL,
                                           related_name='subprocess_cases')  # Subprocess being executed
    # assigned_to_users =  models.ForeignKey(User, on_delete=models.CASCADE)
    assigned_users = models.ManyToManyField('UserData', related_name='cases', blank=True,
                                            )  # Many-to-many relationship
    user_case_history = models.JSONField(blank=True, default=list, null=True)
    parent_case_data = models.JSONField(blank=True,null=True) # added to populate parent case data

    case_data_comments = models.JSONField(blank=True, default=list,null=True)

    # 08-10-2025 by Harish (Indexing for enhancement)[Project TI]
    class Meta:
        indexes = [
            # Common individual filters
            models.Index(fields=['organization']),
            models.Index(fields=['processId']),
            models.Index(fields=['status']),
            models.Index(fields=['stages']),
            models.Index(fields=['id']),

            # Common composite filters for dashboard
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['organization', 'stages']),
            models.Index(fields=['organization', 'processId']),
            models.Index(fields=['organization', 'created_on']),
        ]

    def __str__(self):
        return f"(Case_ID: {self.id}) - {self.stages}"
        # return str(self.id)


class FormDataInfo(models.Model):
    """
    form data records
    """
    Form_uid = models.CharField(max_length=500, blank=True)
    form_description = models.CharField(max_length=500, blank=True)
    # heading = models.CharField(max_length=200, blank=True)
    # subheading = models.CharField(max_length=200, blank=True)
    # logo = models.URLField(blank=True)
    # menu_name = models.CharField(max_length=200, blank=True)
    form_name = models.CharField(max_length=200, blank=True)
    form_json_schema = models.JSONField(blank=True, null=True)
    form_style_schema = models.JSONField(blank=True, null=True)
    form_status = models.BooleanField(default=False)
    form_created_by = models.CharField(default="admin", max_length=200, blank=True)
    form_created_on = models.DateField(default=date.today)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='form_data_info', blank=True, null=True)
    processId = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    # usergroup = models.ManyToManyField('custom_components.UserGroup', on_delete=models.CASCADE,
    #                               related_name='usergroup_form_data_info', blank=True, null=True)

    user_groups = models.ManyToManyField('custom_components.UserGroup', through='FormPermission',
                                         related_name='usergroup_form_data_info', blank=True)
    core_table = models.BooleanField(default=False)
    form_filter_schema = models.JSONField(blank=True, null=True)
    form_send_mail = models.BooleanField(default=False)
    form_send_mail_schema = models.JSONField(blank=True, null=True)
    #process_table_configuration = jsonfield.JSONField(blank=True) # added on 31.3.25 to include table config
    def __str__(self):
        #return f" (Form Name: {self.form_name}), Organization: {self.organization.org_name}"
         return str(self.id)


class UserFormSchema(models.Model):
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='user_form_schema', blank=True, null=True)
    user_form_schema = models.JSONField()
    uid = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)



class UserData(models.Model):
    """
    user details database models
    """
    user_name = models.CharField(max_length=200, blank=True)
    mail_id = models.EmailField(unique=True)
    password = models.CharField(max_length=200, blank=True)
    # profile_pic = models.CharField(max_length=300, blank=True)
    profile_pic = models.TextField(blank=True, null=True)  # modified to store profile pic in backend
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='user_data', blank=True, null=True)
    usergroup = models.ForeignKey('custom_components.UserGroup', on_delete=models.CASCADE,
                                  related_name='usergroup_user_data', blank=True,
                                  null=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True,
                                null=True)  # Add this line
    is_lead = models.BooleanField(default=False, blank=True,
                                  null=True)  # Flag to indicate if the user is a lead
    user_profile_schema = models.JSONField(blank=True, null=True) # added to store user profile details
    # user = models.ForeignKey(User, on_delete=models.CASCADE)
    # phone_number = models.CharField(max_length=10, blank=True)
    # created_at = models.DateTimeField(auto_now_add=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return str(self.user_name)


class FormPermission(models.Model):
    user_group = models.ForeignKey('custom_components.UserGroup', on_delete=models.CASCADE,
                                   related_name='form_permission')
    form = models.ForeignKey(FormDataInfo, on_delete=models.CASCADE)
    read = models.BooleanField(default=False)
    write = models.BooleanField(default=False)
    edit = models.BooleanField(default=False)

    class Meta:
        unique_together = ('user_group', 'form')


# adding this for process and case management TWS:
class FilledFormData(models.Model):
    """
    filled data models of users
    """
    formId = models.CharField(max_length=200, blank=True)
    userId = models.ForeignKey(UserData, on_delete=models.CASCADE, null=True, blank=True)
    processId = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    caseId = models.ForeignKey(Case, on_delete=models.CASCADE, null=True, blank=True)
    data_json = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='filled_data', blank=True, null=True)

    CHOICES = (
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
    )
    status = models.CharField(max_length=500, choices=CHOICES, null=True, blank=True)
    # user_groups = models.ForeignKey('custom_components.UserGroup', on_delete=models.CASCADE,
    #                                      related_name='usergroup_filled_form_data', blank=True,null=True)
    user_groups = models.ManyToManyField('custom_components.UserGroup',
                                         related_name='usergroup_filled_form_data', blank=True)
    
    core_filled_data = models.BooleanField(default=False, blank=True, null=True)
    is_enabled = models.BooleanField(default=False, blank=True, null=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        indexes = [
            GinIndex(fields=['data_json']),
            models.Index(fields=['organization']),
            models.Index(fields=['processId']),
            models.Index(fields=['caseId']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return str(self.id)


# adding this for process and case management TWS:
class Rule(models.Model):
    """
    rule management
    """
    processId = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    ruleId = models.CharField(max_length=200, blank=True)
    rule_type = models.CharField(max_length=200, blank=True)
    rule_json_schema = models.JSONField(blank=True, null=True)
    form_rule_schema = models.JSONField(blank=True, null=True)  ## form level rule will be in XML
    process_codeblock_schema = models.JSONField(blank=True, null=True)  ## added for process code config
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='rule', blank=True, null=True)
    #form = models.ForeignKey(FormDataInfo, on_delete=models.CASCADE,null=True,blank=True)
    form = models.ForeignKey(FormDataInfo, on_delete=models.SET_NULL, null=True, blank=True)
    def __str__(self):
         return str(self.id)
    #def __str__(self):
     #   return f" (Rule: {self.ruleId}), Organization: {self.organization.org_name}"


class NotificationConfig(models.Model):
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='notify', blank=True, null=True)

    # Store email settings as JSON
    config_details = models.JSONField()
    uid = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"NotificationConfig {self.id}"


###### Notification Model By Mohan on 18.3.25

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('Email', 'Email'),
        ('In-App', 'In-App'),
    ]

    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    notification_name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=255, unique=True)
    notification_content = models.TextField(blank=False, null=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    uid = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.notification_name


###### NotificationDismiss Model By Mohan on 18.3.25
class NotificationDismiss(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    notification = models.ForeignKey(Notification, on_delete=models.CASCADE)
    process = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, null=True, blank=True)
    is_dismissed = models.BooleanField(default=False)
    dismissed_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'notification', 'process', 'case')  # Prevent duplicate entries
    #def __str__(self):
     #   return self.user

# adding this for process and case management TWS:
class Sla(models.Model):
    """
    rule management
    """
    processId = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    caseId = models.ForeignKey(Case, on_delete=models.CASCADE, null=True, blank=True)
    slaId = models.CharField(max_length=200, blank=True)
    sla_json_schema = models.JSONField(blank=True, null=True)

    def __str__(self):
        return str(self.id)



################# Adding End Element Table 17.6.2025
class EndElement(models.Model):
    element_type = models.CharField(max_length=200, blank=True, null=True)
    element_uid = models.CharField(max_length=255, blank=True, null=True)
    element_name = models.CharField(max_length=255,  blank=True, null=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='endElement', blank=True, null=True)
    process = models.ForeignKey(CreateProcess, on_delete=models.CASCADE, null=True, blank=True)
    end_element_schema = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)
    
    class Meta:
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['element_uid']),
            models.Index(fields=['process']),
            models.Index(fields=['organization', 'element_uid']),
            models.Index(fields=['organization', 'process']),
        ]


################# Adding Sequence ID Generator

class Sequence(models.Model):
    digit = models.IntegerField()
    name = models.CharField(max_length=100, blank=True)
    prefix = models.CharField(max_length=50, blank=True)
    suffix = models.CharField(max_length=50, blank=True)
    access_id = models.CharField(max_length=100, blank=True,unique=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE,
                                     related_name='sequence', blank=True, null=True)
    counter = models.IntegerField(default=1)  # <-- new field
    uid = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name

################## Table to store the Instance IP of AWS #####################
class ConfigTab(models.Model):
    """
    Config Details - which contains IP of the instance
    """
    instance_name = models.CharField(max_length=200, blank=True)
    Instance_IP = models.CharField(max_length=200, blank=True)
    Instance_url = models.TextField()

    def __str__(self):
        return str(self.id)


