from django.urls import path
from .views import *

urlpatterns = [
    # GET all
    path('sla/list/', SlaAPIView.as_view(), name='sla-list'),

    # POST new
    path('sla/create/', SlaAPIView.as_view(), name='sla-create'),

    # GET single
    path('sla/detail/<int:sla_id>/', SlaAPIView.as_view(), name='sla-detail'),

    # PUT update
    path('sla/update/<int:sla_id>/', SlaAPIView.as_view(), name='sla-update'),

    # DELETE
    path('sla/delete/<int:sla_id>/', SlaAPIView.as_view(), name='sla-delete'),

    path('sla/evaluate_slas/', EvaluateSLAAPIView.as_view(), name='evaluate_slas_api'),

    path('mail_automation/', MailAutomationView.as_view(), name='mail_automation'),

]
