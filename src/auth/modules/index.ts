// The optional modules. Import only what you use; an app without modules bundles none of this.
export { mail, resendMailer, consoleMailer, memoryMailer, sendMail, DEFAULT_TEMPLATES, type Mailer, type MailMessage, type MailOptions, type Templates, type TemplateName } from './mail';
export { emailVerification, confirmEmail, type EmailVerificationOptions } from './email';
export { admin, requireAdmin, adminAction, listUsers, type AdminOptions, type SignupMode, type AdminAction } from './admin';
export { invites, createInvite, createSignupLink, inspectInvite, inspectLink, type InvitesOptions } from './invites';
