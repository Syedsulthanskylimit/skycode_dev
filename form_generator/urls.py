"""
author : mohan
app_name : form_generator
"""

from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views  # function based
from .utils.case_list_api import ProcessCaseListApi
from .views import *
from .views import CustomPasswordResetView
from .utils.dashboard_cases_api import *
urlpatterns = [

    # mohan_dev class based
    path('create_form/', FormGeneratorAPIView.as_view(), name='form_generator_create'),
    # create forms and get all records
    path('create_form/organization/<int:organization_id>/<int:form_id>/', FormGeneratorAPIView.as_view(),
         name='form_data_edit'),  # to edit,delete and list the form
    path('create_form/organization/<int:organization_id>/', FormGeneratorAPIView.as_view(),
         name='forms_by_organization'),  # to list the form based on organization

    path('form_data_count/', get_form_data_count, name='form_data_count'),  # get form data count
    path('send_mail/<int:pk>/', FormGeneratorAPIView.as_view(), name='form_generator_send_mail'),
    # edit ID based form records

    # User created by Admin based on organization and usergroup starts
    path('create-user/', UserCreateView.as_view(), name='create-user'),  # to create a user by Admin
    path('users_list/<int:organization_id>/', UserCreateView.as_view(), name='user-list-by-organization'),
    path('user_list/<int:organization_id>/<int:user_id>/', UserCreateView.as_view()),  # For retrieve, update, delete
    path('users/filter/', filter_users, name='filter-users'),  # To filter the users based on usergroups
    # User created by Admin based on organization and usergroup ends

    # tws bgn
    # mohan_dev
    path('start_process/', CreateProcessView.as_view(), name='create_process'),
    path('start_process/<int:pk>/', CreateProcessView.as_view(), name='get_process'),  # to initiate the process

    path('api/login/', LoginView.as_view(), name='login'),
    path('api/login/<organization_id>/', LoginView.as_view(), name='login'),

    path('password-reset/<int:user_id>/<str:token>/', CustomPasswordResetView.as_view(), name='password_reset'),
    # praba_dev
    path('organizations/<int:organization_id>/cases/', OrganizationCasesView.as_view(), name='organization_cases'),
    path('case_details/<int:organization_id>/<int:process_id>/<int:case_id>/', CaseDetailView.as_view(),
         name='case-detail'),  # get the case details of parent cases.
    path('subprocess_case_details/<int:organization_id>/<int:process_id>/<int:parent_case_id>/cases/',
         CaseDetailsBySubprocessView.as_view(), name='subprocess_case_details'),
    # get the case details of subprocess cases

    path('process_related_cases/', CaseRelatedFormView.as_view(), name='case_related_forms'),
    # path('get_case_related_forms/<int:pk>/<str:token>/', CaseRelatedFormView.as_view(), name='case_related_forms'),  # token
    path('cases/<int:organization_id>/<int:process_id>/', CaseRelatedFormView.as_view(), name='case-list'),  # get
    # cases related to process
    path('cases_related_form/<int:organization_id>/<int:process_id>/<int:pk>/', CaseRelatedFormView.as_view(),
         name='case-detail'),  # get particular cases related to process
    path('approve_mail_by_token/<int:pk>/', CaseRelatedFormView.as_view(),
         name='approve_mail_by_token'),
    path('process_related_cases/<int:pk>/', CaseRelatedFormView.as_view(), name='case_related_forms'),
    path('cases/<int:process_id>/<int:case_id>/assign/', assign_case_to_users, name='assign-case'),
    # assign case for multiple user URL
    path('cases/<int:process_id>/<int:case_id>/comments/', get_case_comments, name='case_comments'),
    path('cases/<int:process_id>/<int:case_id>/user_case_history/', get_user_case_history, name='user_case_history'),
    path('send_sla_email/', sla_email, name='sla_email'),

    path('notifications/', NotificationConfigAPI.as_view(), name='notification-list-create'),  # Notification api
    path('notifications/<int:pk>/', NotificationConfigAPI.as_view(), name='notification-detail'),
    # Notification list API

    # praba_dev
    path('filled_data/', UserFilledDataView.as_view(), name='filled_form_list'),  # List all filled data
    path('filled_data/<int:organization_id>/', UserFilledDataView.as_view(), name='filled_form_by_org'),
    # Filter by organization
    path('filled_data/<int:organization_id>/<int:pk>/', UserFilledDataView.as_view(), name='filled_form_detail'),
    # Filter by organization and pk
    # URL for getting filled forms based on organization alone or a specific filled form by its ID

    path('filled_forms/<int:organization_id>/<int:form_id>/', FilledFormDataView.as_view(), name='filled_form'),
    # to get and post user filled form data based on organization
    path('filled_forms/<int:organization_id>/<int:form_id>/<int:pk>/', FilledFormDataView.as_view(),
         name='filled_data-save'),  # to edit,update and delete

    path('coredata/', CoreData.as_view(), name='core_data'),
    path('coredata/<int:pk>/', CoreDataFilledForm.as_view(), name='core_data_save'),
    ############ URL to explore OCR component as API
    path('components_proxy_api/', components_proxy_api, name='components_api'),
    ########## URL for Notifications by Mohan on 18.3.25
    path('notifications/', NotificationAPIView.as_view(), name='notification_list_create'),
    path('notifications/<int:pk>/', NotificationAPIView.as_view(), name='notification_detail'),
    # Notifications - In-App
    path('notifications/in-app/<int:user_id>/', InAppNotificationAPIView.as_view(), name='in_app_notifications'),
    # Notifications - In-App(Dismiss)

    path('notifications/dismiss/', DismissNotificationAPIView.as_view(), name='dismiss_notification'),  ## dismiss all

    path('core-data/<int:organization_id>/', CoreFormDataInfoListView.as_view(), name='core-table-info'),
    path('core-data/<int:organization_id>/<int:form_id>/', CoreFormDataInfoListView.as_view(), name='coredata-detail'),


    path('core_filled_data/', CoreFilledDataView.as_view(), name='filled_form_list'),  # List all filled data
    path('core_filled_data/<int:organization_id>/', CoreFilledDataView.as_view(), name='filled_form_by_org'),
    # Filter by organization
    path('core_filled_data/<int:organization_id>/<int:pk>/', CoreFilledDataView.as_view(), name='filled_form_detail'),
    # Filter by organization and pkcases
    # URL for getting filled forms based on organization alone or a specific filled form by its ID
    path('user-form-schema/', UserFormSchemaListCreateView.as_view(), name='user_form_schema_list_create'),
    #path('user-form-schema/<int:id>/', UserFormSchemaDetailView.as_view(), name='user_form_schema_detail'),
    path('core_filled_form/<int:organization_id>/<int:form_id>/', CoreFilledFormDataView.as_view(), name='filled_form'),
    # to get and post user filled form data based on organization
    path('core_filled_forms/<int:organization_id>/<int:form_id>/<int:pk>/', CoreFilledFormDataView.as_view(),
         name='filled_data-save'),  # to edit,update and delete
        path('sequence/', SequenceIDConfigAPIView.as_view()),  # list or create
    path('sequence/<int:pk>/', SequenceIDConfigAPIView.as_view()),  # get or edit

    path('generate-id/', GenerateSequenceIdView.as_view()),
    path('update-core-data/<int:form_id>/', UpdateCoreDataView.as_view(), name='update-core-data'),
    path('case-chat-history/<int:pk>/chat/', CaseChatHistoryAPI.as_view(), name='case-chat-history'), # case data history url
    path('approve-mail/<str:case_id>/<uuid:mail_token_id>/', ApproveMailView.as_view(), name='approve-mail'),

    path('form-proceed/<str:token>/', views.proceed_form_view, name='form-proceed-view'),
    path(
        'form-mail-submit/<int:org_id>/<int:process_id>/<int:case_id>/<str:token>/<str:form_uid>',
        FormMailSubmitView.as_view(),
        name='form-mail-submit'
    ),
    path('update-case-global-data/', UpdateCaseGlobalDataView.as_view(),
         name='update_case_global_data'),
    path('organizations/<int:organization_id>/subprocesses/', SubprocessListView.as_view()), # to list the subprocess
    path('case-chat-history/<int:pk>/chat/', CaseChatHistoryAPI.as_view(), name='case-chat-history'),
    path('organizations/process-case-list/<int:organization_id>/<int:process_id>/', ProcessCaseListApi.as_view()),
    path('user-dashboard-list-cases/<int:organization_id>/', DashboardCasesView.as_view(), name='user-dashboard-list-cases'),# default client dashboard api
     # Existing Dashboard with modified response 24-09-2025 by Harish [Product Level]
    path('dashboard/<int:organization_id>/cases/', DashboardDetailView.as_view(), name='dashboard-case-list'),
    
    path("organizations/<int:organization_id>/processes/<int:process_id>/update-fin-amount/",
         CaseFinanceAmountUpdateAPIView.as_view(),
         name="update-fin-amount", ),  # update only fin_amount based on BS_CODE

     path('prompt_bot/', PromptBotView.as_view(), name='prompt-bot'),
     path('model_list/', ModelListView.as_view(), name='model-list'),


]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
