from django.db import models
from django.core.validators import EmailValidator, URLValidator
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.core.exceptions import ValidationError
import uuid
from datetime import timedelta


class Member(models.Model):
    """
    Core Member model for managing membership information.
    Tracks member profile, status, and membership lifecycle.
    """
    
    # Status choices for member lifecycle
    STATUS_CHOICES = (
        ('pending', _('Pending')),
        ('active', _('Active')),
        ('inactive', _('Inactive')),
        ('suspended', _('Suspended')),
        ('expired', _('Expired')),
        ('rejected', _('Rejected')),
    )
    
    MEMBERSHIP_TYPE_CHOICES = (
        ('individual', _('Individual')),
        ('organization', _('Organization')),
        ('student', _('Student')),
        ('associate', _('Associate')),
    )
    
    # Primary identifiers
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    member_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_("Unique member identification number")
    )
    
    # Personal information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        db_index=True
    )
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )
    alternative_phone = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )
    
    # Organization/Individual info
    membership_type = models.CharField(
        max_length=20,
        choices=MEMBERSHIP_TYPE_CHOICES,
        default='individual'
    )
    organization_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text=_("Name of organization for organization memberships")
    )
    
    # Address information
    street_address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state_province = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    
    # Professional information
    professional_title = models.CharField(max_length=255, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    website = models.URLField(
        blank=True,
        null=True,
        validators=[URLValidator()]
    )
    
    # Membership details
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        db_index=True
    )
    membership_level = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text=_("e.g., Gold, Silver, Bronze")
    )
    
    # Dates
    date_joined = models.DateTimeField(auto_now_add=True)
    date_of_birth = models.DateField(blank=True, null=True)
    membership_start_date = models.DateField(
        blank=True,
        null=True,
        help_text=_("When membership becomes active")
    )
    membership_end_date = models.DateField(
        blank=True,
        null=True,
        help_text=_("When membership expires")
    )
    last_renewal_date = models.DateTimeField(blank=True, null=True)
    
    # Verification
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    # Additional fields
    referral_source = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text=_("How the member found out about us")
    )
    internal_notes = models.TextField(
        blank=True,
        null=True,
        help_text=_("Internal notes visible to staff only")
    )
    
    # Audit fields
    created_by = models.CharField(max_length=255, blank=True, null=True)
    updated_by = models.CharField(max_length=255, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['status', 'is_active']),
            models.Index(fields=['email']),
            models.Index(fields=['member_number']),
            models.Index(fields=['membership_end_date']),
        ]
        verbose_name = _("Member")
        verbose_name_plural = _("Members")
        permissions = [
            ("can_approve_membership", "Can approve membership applications"),
            ("can_suspend_member", "Can suspend members"),
            ("can_view_member_documents", "Can view member documents"),
            ("can_export_members", "Can export member data"),
        ]
    
    def __str__(self):
        return f"{self.member_number} - {self.get_full_name()}"
    
    def get_full_name(self):
        """Return the member's full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    def is_membership_expired(self):
        """Check if member's membership has expired."""
        if self.membership_end_date:
            return timezone.now().date() > self.membership_end_date
        return False
    
    def is_membership_active(self):
        """Check if membership is currently active."""
        return (
            self.status == 'active' and
            self.is_active and
            not self.is_membership_expired()
        )
    
    def days_until_expiry(self):
        """Calculate days until membership expires."""
        if self.membership_end_date:
            delta = self.membership_end_date - timezone.now().date()
            return delta.days
        return None
    
    def is_expiring_soon(self, days=30):
        """Check if membership is expiring within specified days."""
        days_left = self.days_until_expiry()
        if days_left is not None:
            return 0 <= days_left <= days
        return False
    
    def renew_membership(self, days=365):
        """Renew membership for specified number of days."""
        if self.membership_end_date:
            new_end_date = self.membership_end_date + timedelta(days=days)
        else:
            new_end_date = timezone.now().date() + timedelta(days=days)
        
        self.membership_end_date = new_end_date
        self.last_renewal_date = timezone.now()
        self.status = 'active'
        self.save()
    
    def suspend_membership(self, reason=None):
        """Suspend the membership."""
        self.status = 'suspended'
        if reason:
            self.internal_notes = f"Suspension reason: {reason}\n{self.internal_notes or ''}"
        self.save()
    
    def activate_membership(self):
        """Activate the membership."""
        self.status = 'active'
        self.is_active = True
        self.save()
    
    def deactivate_membership(self):
        """Deactivate the membership."""
        self.status = 'inactive'
        self.is_active = False
        self.save()
    
    def get_documents(self):
        """Get all documents associated with this member."""
        return self.documents.all()
    
    def has_required_documents(self):
        """Check if member has all required documents."""
        required_types = ['id', 'proof_of_address']
        for doc_type in required_types:
            if not self.documents.filter(document_type=doc_type).exists():
                return False
        return True
    
    def clean(self):
        """Validate member data."""
        if self.membership_type == 'organization' and not self.organization_name:
            raise ValidationError(
                _("Organization name is required for organization memberships")
            )
        
        if self.membership_start_date and self.membership_end_date:
            if self.membership_start_date > self.membership_end_date:
                raise ValidationError(
                    _("Membership start date must be before end date")
                )


class MemberDocument(models.Model):
    """
    Model for storing member verification documents.
    Tracks document type, upload date, and verification status.
    """
    
    DOCUMENT_TYPE_CHOICES = (
        ('id', _('Government ID')),
        ('passport', _('Passport')),
        ('proof_of_address', _('Proof of Address')),
        ('business_license', _('Business License')),
        ('certificate', _('Certificate')),
        ('reference_letter', _('Reference Letter')),
        ('other', _('Other')),
    )
    
    VERIFICATION_STATUS_CHOICES = (
        ('pending', _('Pending')),
        ('verified', _('Verified')),
        ('rejected', _('Rejected')),
        ('expired', _('Expired')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    member = models.ForeignKey(
        Member,
        on_delete=models.CASCADE,
        related_name='documents'
    )
    document_type = models.CharField(
        max_length=50,
        choices=DOCUMENT_TYPE_CHOICES
    )
    document_file = models.FileField(
        upload_to='member_documents/%Y/%m/%d/',
        help_text=_("PDF, JPG, PNG files accepted")
    )
    document_number = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text=_("ID number, passport number, etc.")
    )
    issue_date = models.DateField(blank=True, null=True)
    expiry_date = models.DateField(blank=True, null=True)
    
    # Verification
    verification_status = models.CharField(
        max_length=20,
        choices=VERIFICATION_STATUS_CHOICES,
        default='pending'
    )
    verified_by = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text=_("Name of person who verified the document")
    )
    verified_at = models.DateTimeField(blank=True, null=True)
    rejection_reason = models.TextField(
        blank=True,
        null=True,
        help_text=_("Reason for rejection if applicable")
    )
    
    # Audit
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['member', 'document_type']),
            models.Index(fields=['verification_status']),
        ]
        verbose_name = _("Member Document")
        verbose_name_plural = _("Member Documents")
        unique_together = [['member', 'document_type', 'document_number']]
    
    def __str__(self):
        return f"{self.member.member_number} - {self.get_document_type_display()}"
    
    def is_document_expired(self):
        """Check if document has expired."""
        if self.expiry_date:
            return timezone.now().date() > self.expiry_date
        return False
    
    def verify_document(self, verified_by):
        """Mark document as verified."""
        self.verification_status = 'verified'
        self.verified_by = verified_by
        self.verified_at = timezone.now()
        self.save()
    
    def reject_document(self, rejection_reason):
        """Reject document with reason."""
        self.verification_status = 'rejected'
        self.rejection_reason = rejection_reason
        self.save()
    
    def expire_document(self):
        """Mark document as expired."""
        self.verification_status = 'expired'
        self.save()
    
    def get_file_extension(self):
        """Get the file extension."""
        return self.document_file.name.split('.')[-1].lower()
    
    def clean(self):
        """Validate document data."""
        if self.issue_date and self.expiry_date:
            if self.issue_date > self.expiry_date:
                raise ValidationError(
                    _("Document issue date must be before expiry date")
                )


class MembershipApproval(models.Model):
    """
    Model for tracking membership approval workflow.
    Manages the approval process from application to activation.
    """
    
    STATUS_CHOICES = (
        ('submitted', _('Submitted')),
        ('under_review', _('Under Review')),
        ('approved', _('Approved')),
        ('rejected', _('Rejected')),
        ('pending_documents', _('Pending Documents')),
    )
    
    APPROVAL_LEVEL_CHOICES = (
        ('level1', _('Level 1 - Admin Review')),
        ('level2', _('Level 2 - Manager Review')),
        ('level3', _('Level 3 - Director Review')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    member = models.OneToOneField(
        Member,
        on_delete=models.CASCADE,
        related_name='approval'
    )
    
    # Application details
    application_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='submitted',
        db_index=True
    )
    approval_level = models.CharField(
        max_length=20,
        choices=APPROVAL_LEVEL_CHOICES,
        default='level1'
    )
    
    # Approval workflow
    submitted_by = models.CharField(max_length=255)
    reviewed_by = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )
    approved_by = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )
    
    # Dates
    review_date = models.DateTimeField(blank=True, null=True)
    approval_date = models.DateTimeField(blank=True, null=True)
    rejection_date = models.DateTimeField(blank=True, null=True)
    
    # Notes and reasons
    application_notes = models.TextField(
        blank=True,
        null=True,
        help_text=_("Notes from the application")
    )
    review_comments = models.TextField(
        blank=True,
        null=True,
        help_text=_("Comments from reviewer")
    )
    rejection_reason = models.TextField(
        blank=True,
        null=True,
        help_text=_("Reason for rejection")
    )
    approval_conditions = models.TextField(
        blank=True,
        null=True,
        help_text=_("Any conditions for approval")
    )
    
    # Document requirements
    documents_submitted = models.BooleanField(default=False)
    all_documents_verified = models.BooleanField(default=False)
    
    # Reference checks
    reference_check_completed = models.BooleanField(default=False)
    reference_check_notes = models.TextField(blank=True, null=True)
    
    # Additional
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-application_date']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['member']),
        ]
        verbose_name = _("Membership Approval")
        verbose_name_plural = _("Membership Approvals")
    
    def __str__(self):
        return f"Approval - {self.member.member_number} ({self.status})"
    
    def submit_for_review(self, reviewer_name):
        """Submit application for review."""
        self.status = 'under_review'
        self.reviewed_by = reviewer_name
        self.review_date = timezone.now()
        self.save()
    
    def approve(self, approver_name, conditions=None):
        """Approve the membership application."""
        self.status = 'approved'
        self.approved_by = approver_name
        self.approval_date = timezone.now()
        if conditions:
            self.approval_conditions = conditions
        self.member.status = 'active'
        self.member.save()
        self.save()
    
    def reject(self, rejection_reason):
        """Reject the membership application."""
        self.status = 'rejected'
        self.rejection_reason = rejection_reason
        self.rejection_date = timezone.now()
        self.member.status = 'rejected'
        self.member.save()
        self.save()
    
    def request_documents(self):
        """Mark as pending documents."""
        self.status = 'pending_documents'
        self.save()
    
    def mark_documents_submitted(self):
        """Mark documents as submitted."""
        self.documents_submitted = True
        self.save()
    
    def verify_all_documents(self):
        """Mark all required documents as verified."""
        self.all_documents_verified = True
        self.save()
    
    def complete_reference_check(self, notes=None):
        """Complete reference check."""
        self.reference_check_completed = True
        if notes:
            self.reference_check_notes = notes
        self.save()
    
    def get_approval_progress(self):
        """Get approval progress percentage."""
        completed_items = 0
        total_items = 0
        
        checks = [
            self.documents_submitted,
            self.all_documents_verified,
            self.reference_check_completed,
            self.status == 'approved'
        ]
        
        for check in checks:
            total_items += 1
            if check:
                completed_items += 1
        
        return int((completed_items / total_items) * 100) if total_items > 0 else 0
    
    def is_approval_complete(self):
        """Check if approval process is complete."""
        return self.status == 'approved'


class MembershipRenewal(models.Model):
    """
    Model for tracking membership renewal.
    Manages renewal notifications, payments, and status updates.
    """
    
    STATUS_CHOICES = (
        ('pending', _('Pending')),
        ('notified', _('Notified')),
        ('in_progress', _('In Progress')),
        ('completed', _('Completed')),
        ('declined', _('Declined')),
        ('expired', _('Expired')),
    )
    
    RENEWAL_FREQUENCY_CHOICES = (
        ('annual', _('Annual')),
        ('biennial', _('Biennial')),
        ('triennial', _('Triennial')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    member = models.ForeignKey(
        Member,
        on_delete=models.CASCADE,
        related_name='renewals'
    )
    
    # Renewal details
    renewal_cycle = models.CharField(
        max_length=20,
        choices=RENEWAL_FREQUENCY_CHOICES,
        default='annual'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        db_index=True
    )
    
    # Dates
    renewal_due_date = models.DateField(db_index=True)
    renewal_start_date = models.DateField(blank=True, null=True)
    renewal_completion_date = models.DateField(blank=True, null=True)
    last_notification_date = models.DateTimeField(blank=True, null=True)
    
    # Renewal period
    previous_end_date = models.DateField(
        help_text=_("Previous membership end date")
    )
    new_end_date = models.DateField(
        blank=True,
        null=True,
        help_text=_("New membership end date after renewal")
    )
    
    # Financial
    renewal_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00
    )
    payment_status = models.CharField(
        max_length=20,
        choices=(
            ('pending', _('Pending')),
            ('received', _('Received')),
            ('cancelled', _('Cancelled')),
        ),
        default='pending'
    )
    payment_date = models.DateField(blank=True, null=True)
    payment_reference = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    
    # Renewal process
    notification_sent = models.BooleanField(default=False)
    reminder_count = models.IntegerField(default=0, help_text=_("Number of reminders sent"))
    documents_required = models.BooleanField(default=False)
    documents_submitted = models.BooleanField(default=False)
    
    # Notes
    renewal_notes = models.TextField(blank=True, null=True)
    decline_reason = models.TextField(blank=True, null=True)
    
    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        ordering = ['-renewal_due_date']
        indexes = [
            models.Index(fields=['member', 'status']),
            models.Index(fields=['renewal_due_date']),
            models.Index(fields=['status']),
        ]
        verbose_name = _("Membership Renewal")
        verbose_name_plural = _("Membership Renewals")
    
    def __str__(self):
        return f"Renewal - {self.member.member_number} ({self.status})"
    
    def is_overdue(self):
        """Check if renewal is overdue."""
        return self.renewal_due_date < timezone.now().date() and self.status != 'completed'
    
    def days_until_due(self):
        """Calculate days until renewal is due."""
        delta = self.renewal_due_date - timezone.now().date()
        return delta.days
    
    def is_due_soon(self, days=30):
        """Check if renewal is due within specified days."""
        days_left = self.days_until_due()
        return 0 <= days_left <= days
    
    def send_notification(self, notified_by):
        """Send renewal notification."""
        self.notification_sent = True
        self.last_notification_date = timezone.now()
        self.status = 'notified'
        self.created_by = notified_by
        self.save()
    
    def send_reminder(self):
        """Send renewal reminder."""
        self.reminder_count += 1
        self.last_notification_date = timezone.now()
        self.save()
    
    def start_renewal(self):
        """Start the renewal process."""
        self.status = 'in_progress'
        self.renewal_start_date = timezone.now().date()
        self.save()
    
    def complete_renewal(self):
        """Complete the renewal process."""
        self.status = 'completed'
        self.renewal_completion_date = timezone.now().date()
        self.payment_status = 'received'
        
        # Update member membership dates
        self.member.membership_start_date = self.renewal_start_date
        self.member.membership_end_date = self.new_end_date
        self.member.last_renewal_date = timezone.now()
        self.member.save()
        
        self.save()
    
    def decline_renewal(self, reason=None):
        """Decline renewal."""
        self.status = 'declined'
        if reason:
            self.decline_reason = reason
        self.member.status = 'expired'
        self.member.save()
        self.save()
    
    def expire_renewal(self):
        """Expire renewal if not completed by due date."""
        self.status = 'expired'
        self.save()
    
    def process_payment(self, payment_reference):
        """Process renewal payment."""
        self.payment_status = 'received'
        self.payment_date = timezone.now().date()
        self.payment_reference = payment_reference
        self.save()
    
    def get_renewal_progress(self):
        """Get renewal progress percentage."""
        completed_items = 0
        total_items = 4
        
        if self.notification_sent:
            completed_items += 1
        if not self.documents_required or self.documents_submitted:
            completed_items += 1
        if self.payment_status == 'received':
            completed_items += 1
        if self.status == 'completed':
            completed_items += 1
        
        return int((completed_items / total_items) * 100)
    
    def clean(self):
        """Validate renewal data."""
        if self.new_end_date and self.renewal_start_date:
            if self.renewal_start_date > self.new_end_date:
                raise ValidationError(
                    _("Renewal start date must be before end date")
                )
        
        if self.new_end_date:
            if self.new_end_date <= self.previous_end_date:
                raise ValidationError(
                    _("New end date must be after previous end date")
                )
