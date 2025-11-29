from django.db import models




class SlaConfig(models.Model):
    sla_name = models.CharField(max_length=300, blank=True)
    sla_uid = models.CharField(max_length=300, blank=True)
    organization = models.ForeignKey('custom_components.Organization', on_delete=models.CASCADE, related_name='sla_org',
                                     blank=True,
                                     null=True)
    process_id = models.ForeignKey('form_generator.CreateProcess', on_delete=models.CASCADE,
                                related_name='sla_process', blank=True,
                                null=True)
    sla_json_schema=models.JSONField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True,null=True, blank=True)
    created_by = models.CharField(max_length=300, blank=True)
    updated_at=models.DateTimeField(auto_now_add=True,null=True, blank=True)
    updated_by = models.CharField(max_length=300, blank=True)

    def __str__(self):
        return f"SLA - {self.sla_name} Id - {self.id}"

class SlaCaseInstance(models.Model):
    case_id = models.ForeignKey('form_generator.Case', on_delete=models.CASCADE, related_name='case_instance',null=True)
    sla_id = models.ForeignKey(SlaConfig, on_delete=models.CASCADE,null=True, related_name='sla_instance')
    is_completed=models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    created_by = models.CharField(max_length=300, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    updated_by = models.CharField(max_length=300, blank=True)

    def __str__(self):
        return f"SLA Case Instance: {self.case_id if self.case_id else 'N/A'}"


