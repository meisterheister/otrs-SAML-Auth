# --
# Copyright (C) 2001-2018 OTRS AG, https://otrs.com/
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see https://www.gnu.org/licenses/gpl-3.0.txt.
# --
# Enhanced Kernel/System/Auth/HTTPBasicAuth.pm by implementing Auto-provisioning of Users (Agents)
# Provides HTTPBasic authentication for use with Apache's mod_auth_mellon.
# Author: 		Rick H. <heisterhagen@interlake.net>
# Inspired by: 	Dick Visser <visser@terena.org>
#
# Note:
#
# If you use this module, you have to copy the following config settings
# to Kernel/Config.pm and adjust the URI:
# $Self->{'AuthModule'} = 'Kernel::System::Auth::HTTPBasicAuthMellon';
# $Self->{'LoginURL'} = 'https://otrs.example.net/mellon/login?ReturnTo=/index.pl';
# $Self->{'LogoutURL'} = 'https://otrs.example.net/mellon/logout?ReturnTo=http://example.com';
#
# Copy the following lines to Kernel/Config.pm override the environment vars to be used
# and add your SAML attribute name:
# $Self->{'AuthModule::HTTPBasicAuthMellon::UsernameEnvVar'} = 'MELLON_<SAML_ATTRIBUTE_USERNAME>';
# $Self->{'AuthModule::HTTPBasicAuthMellon::MailEnvVar'} = 'MELLON_<SAML_ATTRIBUTE_MAIL>';
# $Self->{'AuthModule::HTTPBasicAuthMellon::FirstNameEnvVar'} = 'MELLON_<SAML_ATTRIBUTE_GIVENNAME>';
# $Self->{'AuthModule::HTTPBasicAuthMellon::LastNameEnvVar'} = 'MELLON_<SAML_ATTRIBUTE_SURNAME>';
# --

package Kernel::System::Auth::HTTPBasicAuthMellon;

use strict;
use warnings;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::Log',
	'Kernel::System::Main',
	'Kernel::System::DB',
	'Kernel::System::Encode',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    $Self->{UserObject} = Kernel::System::User->new( %{$Self} );
    # Mellon environment vars
    $Self->{MailEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get( 'AuthModule::HTTPBasicAuthMellon::MailEnvVar')
    || 'MELLON_mail';
    $Self->{FirstNameEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get('AuthModule::HTTPBasicAuthMellon::FirstNameEnvVar')
    || 'MELLON_givenName';
    $Self->{LastNameEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get( 'AuthModule::HTTPBasicAuthMellon::LastNameEnvVar')
    || 'MELLON_sn';
	
    # Debug 0=off 1=on
    $Self->{Debug} = 1;
    $Self->{Count} = $Param{Count} || '';
    return $Self;
}

sub GetOption {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need What!"
        );
        return;
    }

    # module options
    my %Option = (
        PreAuth => 1,
    );

    # return option
    return $Option{ $Param{What} };
}

sub Auth {
    my ( $Self, %Param ) = @_;
    # Get attributes values from environment variables
    my $User       = $ENV{REMOTE_USER};
    my $Mail       = $ENV{$Self->{MailEnvVar}} || 'invalid_email@noreply.com';
    my $FirstName  = $ENV{$Self->{FirstNameEnvVar}} || 'first_name';
    my $LastName   = $ENV{$Self->{LastNameEnvVar}} || 'last_name';
    my $RemoteAddr = $ENV{REMOTE_ADDR} || 'Got no REMOTE_ADDR env!';
    # return on no user
    if ( !$User ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message =>
                "No \$ENV{REMOTE_USER}, so not authenticated yet. Redirecting to authenticate (client REMOTE_ADDR: $RemoteAddr).",
        );
        return;
    }
    # replace parts of login
    my $Replace = $Kernel::OM->Get('Kernel::Config')->Get(
        'AuthModule::HTTPBasicAuth::Replace' . $Self->{Count},
    );
    if ($Replace) {
        $User =~ s/^\Q$Replace\E//;
    }
    # regexp on login
    my $ReplaceRegExp = $Kernel::OM->Get('Kernel::Config')->Get(
        'AuthModule::HTTPBasicAuth::ReplaceRegExp' . $Self->{Count},
    );
    if ($ReplaceRegExp) {
        $User =~ s/$ReplaceRegExp/$1/;
    }
    # Log Apache environment vars in debug mode
    if ( $Self->{Debug} > 0 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message => 'Apache environment vars:'
        );
        foreach my $var (sort keys %ENV) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message =>   $var . "=" . $ENV{$var},
            );
        }
    }
    # log
    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'notice',
        Message  => "User '$User' Authentication ok (REMOTE_ADDR: $RemoteAddr).",
    );
 
    # Auto-provisiong.
    # First check if customer exists
    my %UserTest = $Self->{UserObject}->GetUserData( User => $User );
    if (! %UserTest) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message  => "User '$User' doesn't have an account here yet, provisioning it now",
        );
        # Add new customer
        my $newuser = $Self->{UserObject}->UserAdd(
            UserFirstname  => $FirstName,
            UserLastname   => $LastName,
            UserLogin      => $User,
            UserPw	   	=> $Self->{UserObject}->GenerateRandomPassword(),
            UserEmail      => $Mail,
            ValidID        => 1,
            ChangeUserID   => 1,
         );
    }
    # return user
    return $User;
}
1;
