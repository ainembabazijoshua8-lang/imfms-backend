"""
Main URL Configuration for IMFMS Backend

This module contains the primary URL routing configuration for the Django application,
including API endpoints and admin routes.
"""

from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# Import viewsets and views
# from apps.api.views import (
#     UserViewSet,
#     AuthenticationView,
# )

# Initialize the router
router = DefaultRouter()

# Register viewsets
# router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API Authentication endpoints
    path('api/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # API Router endpoints
    path('api/', include(router.urls)),
    
    # API v1 endpoints (for versioning)
    path('api/v1/', include([
        # Include app-specific URLs here
        # path('users/', include('apps.users.urls')),
        # path('finance/', include('apps.finance.urls')),
    ])),
    
    # Health check endpoint
    path('health/', lambda request: __import__('django.http').JsonResponse({'status': 'ok'})),
]

# Optional: Serve media files in development
from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
