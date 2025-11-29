from django.conf.urls.static import static
from django.urls import path
from django.conf import settings
from .views import *  # class based
from . import views  # function based
from django.urls import path, include
from django.contrib.auth import views as auth_views

urlpatterns = [
    # added by Mohan BGN
    path('processes/', ProcessBuilder.as_view(), name='process_builder'),

    path('processes/organization/<int:organization_id>/<int:process_id>/', ListProcessesByOrganization.as_view(),
         name='list-processes'
              '-by-organization'),
    path('processes/organization/<int:organization_id>/', ListProcessesByOrganization.as_view(),
         name='list-processes'
              '-by-organization'),
    path('create_process/<int:process_id>/', CreateProcessView.as_view(), name='create_process'),
    # to list the process based elements
    path('processes/create/', CreateProcessView.as_view(), name='create-process'),  # process create
    path('processes/<int:pk>/', ProcessDetailView.as_view(), name='process-detail'),  # process update


    # added by Mohan END

    # bot component URL starts

    path('bots/', BotListCreateView.as_view(), name='bot-list-create'),  # to list and create  the bots
    path('bots/<int:organization_id>/', BotListCreateView.as_view(), name='bot-list-create'),
    path('bots/<int:organization_id>/<int:id>/', BotDetailView.as_view(), name='bot-detail'),  # update and list the bot

    # bot component URL ends

    # integration URL starts
    path('integrations/<int:organization_id>/', views.IntegrationListCreateAPIView.as_view(), name='integration-list-create'),
    path('integrations/<int:organization_id>/<int:pk>/', views.IntegrationDetailAPIView.as_view(), name='integration-detail'),

    # integration URL ends

    # OCR Component URL starts
    path('ocrs/<int:organization_id>/', OcrListCreateView.as_view(), name='ocr-list-create'),  # OCR components
    # create and list
    path('ocrs/<int:organization_id>/<int:pk>/', OcrDetailView.as_view(), name='ocr-detail'),  # OCR components
    # create and list
    # OCR Component URL ends

    # Dashboard URL starts

    path('organizations/<int:organization_id>/process_details/', OrganizationBasedProcess.as_view(), name='organization-details'),
    path('organizations/<int:organization_id>/details/', OrganizationDetailsAPIView.as_view(), name='organization-details'),# organization based details
    path('dashboards/<int:organization_id>/', DashboardListCreateView.as_view(),
         name='dashboard-list-create'),
    path('dashboards/<int:organization_id>/<int:pk>/', DashboardRetrieveUpdateDestroyView.as_view(),
         name='dashboard-detail'),
    path('user_dashboard/<int:organization_id>/<int:usergroup>/', DashboardRetrieveUpdateDestroyView.as_view(), name='dashboard-detail'),

    # Dashboard URL ends

    # DMS URL starts
    path('dms/<int:organization_id>/', DmsListCreateView.as_view(), name='dms-list-create'),
    path('dms/<int:organization_id>/<int:id>/', DmsRetrieveUpdateView.as_view(),
         name='dms-retrieve-update'),
    path('api/dms-data/<int:organization_id>/', DmsDataListView.as_view(), name='dms-data-detail'),
    # to list dms related to organization
    path('api/dms-data/', DmsDataListView.as_view(), name='dms-data-detail'),
    path('api/dms_download/', DMSAPIView.as_view(), name='send_filename'),
    # DMS URL ends

    # added by laxmi praba BGN
    path('drive-files/', views.list_drive_files, name='drive_files_api'),
    path('convert/', views.convert_excel_to_json, name='convert_excel_to_json'),
    path('bot_convert/', views.convert_excel_to_json1, name='convert_excel_to_json_bot'),
    # added by laxmi praba END

    # added by Raji BGN
    path('screen_scraping/', AutomationView.as_view(), name='screen_scraping'),
    # path('api_integration/', APIIntegrationView.as_view(), name='api_integration'),
    # path('api_mailmonitor/', MailMonitorView.as_view(), name='api_mailmonitor'),
    # added by Raji END

    # added by Praba -Scheduler API Starts

    path('api/scheduler/<int:process_id>/<int:organization_id>/', SchedulerCreateAPIView.as_view(), name='create_scheduler'),
    # Retrieve schedulers (GET)
    path('scheduler/<int:process_id>/<int:organization_id>/', SchedulerCreateAPIView.as_view(), name='get_schedulers'),
    # Update scheduler (PUT)
    path('scheduler/<int:process_id>/<int:organization_id>/', SchedulerCreateAPIView.as_view(),name='update_scheduler'),
    # added by Praba -Scheduler API Ends

    # Report URLs starts - added by Praba
    # List all report configs for an organization or create a new one
    path('organizations/<int:organization_id>/report-configs/', ReportConfigView.as_view(), name='report-config-list'),

    # Retrieve, update, or delete a specific report config
    path('organizations/<int:organization_id>/report-configs/<int:pk>/', ReportConfigView.as_view(),
         name='report-config-detail'),
    path('report/<int:organization_id>/<int:report_id>/', GenerateReportView.as_view(), name='report-list'),

    # Report URLs sends - added by Praba
    # added by Raji BGN for DMS components
    path('FileUploadView/',FileUploadView.as_view(),name='FileUploadView'),
    # 30-09-2025 by Harish [Project TI]
    path('sftp_file_download/<int:org_id>/<str:filename>',SFTPFileDownloadView.as_view(),name='SFTPFileDownloadView'),
    # path('FileDownloadView/',FileDownloadView.as_view(),name='FileDownloadView'),
    # added by Raji ENDS for DMS components

    # added by Praba BGN - For Organization
    path('organizations/', views.OrganizationListCreateAPIView.as_view(), name='organization-list-create'),
    path('organizations/<int:pk>/', views.OrganizationRetrieveUpdateAPIView.as_view(),
         name='organization-retrieve-update'),
    path('organization/code/<str:org_code>/', OrganizationRetrieveUpdateAPIView.as_view(), name='organization-detail-by'
                                                                                                '-code'),  # api to get
    # organization using org_code
    # added by Praba END

    # added by Praba BGN - For UserGroups
    path('organizations/<int:org_id>/usergroups/', views.UserGroupListCreateAPIView.as_view(), name='usergroup-list'
                                                                                                    '-create'),  #
    # list the user based on organization

    path('organizations/<int:org_id>/usergroups/<int:pk>/', views.UserGroupRetrieveUpdateDestroyAPIView.as_view(),
         name='usergroup-detail'),  # edit the user based on organization
    path('user-groups/', UserGroupListCreateAPIView.as_view(), name='user-group-list-create'),
    path('user-groups/<int:pk>/', UserGroupRetrieveUpdateDestroyAPIView.as_view(),
         name='user-group-retrieve-update-destroy'),
    # added by Praba END

     path('request-password-reset/', RequestPasswordResetAPIView.as_view(), name='request_password_reset'),

    path('password-reset/<int:user_id>/<str:token>/', auth_views.PasswordResetView.as_view(), name='password_reset1'),

    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset/<str:user_id>/<str:token>/', auth_views.PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    # path('password-reset/confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset/complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('api/password-reset/', initiate_password_reset, name='api_password_reset'),
    # other URLs in your application
    path('execute-code-block/', CodeBlockExecutionAPIView.as_view(), name='execute-script'), ### code block API

    # RPA DESKTOP COMPONENT
   # path('rpa-handler/', RPAHandlerView.as_view(), name='rpa_handler'),
    path('qrcodegenerate/', QRCodeGenerate.as_view(), name='qrcodegenerate/'),
    path("execute-api/", ExecuteDynamicAPI.as_view(), name="execute-api"),
    # Refresh Token URL for Dabico [temp]
    path('notifications_bot/', NotificationBotListCreateView.as_view(), name='notification-list-create'),
    path('notifications_bot/<int:pk>/', NotificationBotDetailView.as_view(), name='notification-detail'),
    path('refresh-token/', refresh_token, name='refresh_token'),
    path('dash-config/client/',ClientDashboardView.as_view(),name='dash-config'),
    path('generate_report/<int:organization_id>/<int:report_id>/', ReportBuilderView.as_view(), name='report-list'), # optimized report generator
    # path('report_optimized/<int:organization_id>/<int:report_id>/', ReportBuilderViewOptimized.as_view(), name='report-list'), # optimized report generator by Mohan

    # agent api
    path('agents/', AgentAPIView.as_view(), name='agent-list-create'),
    path('agents/<int:pk>/', AgentAPIView.as_view(), name='agent-detail'),

     # Export & Import Organization API
     path("export-org/<int:org_id>/", ExportOrganizationDataAPIView.as_view(), name="export_org_api"),
     path("import-org/", ImportOrganizationDataAPIView.as_view(), name="import_org_api"),

     # Export & Import Process API
     path("export-process/<int:organization_id>/", ExportProcessDataAPIView.as_view(), name="export_all_processes",),
     path("export-process/<int:organization_id>/<int:process_id>/", ExportProcessDataAPIView.as_view(), name="export_single_process",)


]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
