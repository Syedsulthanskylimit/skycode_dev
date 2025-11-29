"""
author : mohan
app_name : custom_components
"""
from django.contrib import admin
from .models import *

admin.site.register(Bot)
admin.site.register(BotSchema)
admin.site.register(BotData)
admin.site.register(Integration)
admin.site.register(IntegrationDetails)
admin.site.register(Organization)
admin.site.register(Dashboard)
admin.site.register(Ocr)
admin.site.register(Ocr_Details)
admin.site.register(Dms)
admin.site.register(Dms_data)
admin.site.register(UserGroup)
admin.site.register(Permission)
admin.site.register(Scheduler)
admin.site.register(SchedulerData)
admin.site.register(ReportConfig)
admin.site.register(NotificationBotSchema)
admin.site.register(NotificationData)
admin.site.register(Agent)
