"""
Custom exception handlers for Django REST Framework.

This module provides centralized exception handling for the API,
ensuring consistent error responses across all endpoints.
"""

from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler for DRF.
    
    Provides consistent error response format for all API exceptions.
    
    Args:
        exc: The exception that was raised
        context: Additional context about the request
    
    Returns:
        Response: A DRF Response object with error details
    """
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if response is not None:
        # Extract error details from the response
        error_detail = response.data
        
        # Log the exception
        logger.warning(
            f"API Exception: {exc.__class__.__name__}",
            extra={
                'status_code': response.status_code,
                'error_detail': error_detail,
                'path': context.get('request').path if context.get('request') else None,
                'method': context.get('request').method if context.get('request') else None,
            }
        )
        
        # Format the response consistently
        formatted_response = {
            'success': False,
            'status_code': response.status_code,
            'error': error_detail,
            'message': _get_error_message(exc, response.status_code)
        }
        
        response.data = formatted_response
        
        return response
    
    # If response is None, it's an unhandled exception
    logger.error(
        f"Unhandled Exception: {exc.__class__.__name__}",
        exc_info=True,
        extra={
            'path': context.get('request').path if context.get('request') else None,
            'method': context.get('request').method if context.get('request') else None,
        }
    )
    
    # Return a generic error response for unhandled exceptions
    return Response(
        {
            'success': False,
            'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
            'error': 'An unexpected error occurred',
            'message': 'Please contact support if this issue persists'
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def _get_error_message(exc, status_code):
    """
    Get a user-friendly error message based on the exception and status code.
    
    Args:
        exc: The exception object
        status_code: The HTTP status code
    
    Returns:
        str: A user-friendly error message
    """
    message_map = {
        status.HTTP_400_BAD_REQUEST: 'Invalid request data. Please check your input.',
        status.HTTP_401_UNAUTHORIZED: 'Authentication required. Please log in.',
        status.HTTP_403_FORBIDDEN: 'You do not have permission to perform this action.',
        status.HTTP_404_NOT_FOUND: 'The requested resource was not found.',
        status.HTTP_405_METHOD_NOT_ALLOWED: 'This HTTP method is not allowed.',
        status.HTTP_409_CONFLICT: 'A conflict occurred. Please try again.',
        status.HTTP_429_TOO_MANY_REQUESTS: 'Too many requests. Please try again later.',
        status.HTTP_500_INTERNAL_SERVER_ERROR: 'An internal server error occurred.',
        status.HTTP_503_SERVICE_UNAVAILABLE: 'Service temporarily unavailable. Please try again later.',
    }
    
    return message_map.get(
        status_code,
        f'An error occurred (HTTP {status_code})'
    )


class APIException(Exception):
    """Base exception class for API-specific exceptions."""
    
    def __init__(self, message, status_code=status.HTTP_400_BAD_REQUEST, detail=None):
        """
        Initialize the API exception.
        
        Args:
            message: User-friendly error message
            status_code: HTTP status code (default: 400)
            detail: Additional error details
        """
        self.message = message
        self.status_code = status_code
        self.detail = detail or message
        super().__init__(self.message)


class ValidationException(APIException):
    """Exception for validation errors."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )


class AuthenticationException(APIException):
    """Exception for authentication errors."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail
        )


class PermissionException(APIException):
    """Exception for permission/authorization errors."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )


class ResourceNotFoundException(APIException):
    """Exception for when a requested resource is not found."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail
        )


class ConflictException(APIException):
    """Exception for conflict errors (e.g., duplicate entries)."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )


class RateLimitException(APIException):
    """Exception for rate limiting."""
    
    def __init__(self, message, detail=None):
        super().__init__(
            message=message,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail
        )
