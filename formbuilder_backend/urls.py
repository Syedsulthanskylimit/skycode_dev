"""

"""
from django.contrib import admin
from django.urls import path, include
from form_generator.views import *
from custom_components.views import *
from django.conf.urls.static import static
from django.conf import settings
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('form_generator.urls')),
    path('custom_components/', include('custom_components.urls')),
    path('automation/', include('automation.urls')),


    # JWT Authentication
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
