# --
# Kernel/System/CustomerAuth/HTTPBasicAuthMellon.pm
# Provides HTTPBasic authentication for use with Apache's mod_auth_mellon.
# This module auto-provisions customer users.
# Dick Visser <visser@terena.org> 2014-08-22
# Updated to function with OTRS 6 Rick H. 2018-09-14
# Copyright (C) TERENA, http://www.terena.org
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --
package Kernel::System::CustomerAuth::HTTPBasicAuthMellon;
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

    $Self->{CustomerUserObject} = Kernel::System::CustomerUser->new( %{$Self} );
    # Mellon environment vars
    $Self->{MailEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get( 'Customer::AuthModule::HTTPBasicAuthMellon::MailEnvVar')
    || 'MELLON_mail';
    $Self->{FirstNameEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get('Customer::AuthModule::HTTPBasicAuthMellon::FirstNameEnvVar')
    || 'MELLON_givenName';
    $Self->{LastNameEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get( 'Customer::AuthModule::HTTPBasicAuthMellon::LastNameEnvVar')
    || 'MELLON_sn';
    $Self->{CustomerIDEnvVar}
        = $Kernel::OM->Get('Kernel::Config')->Get( 'Customer::AuthModule::HTTPBasicAuthMellon::CustomerIDEnvVar')
    || 'MELLON_customer_id';
    # Debug 0=off 1=on
    $Self->{Debug} = 1;
    $Self->{Count} = $Param{Count} || '';
    return $Self;
}
sub GetOption {
    my ( $Self, %Param ) = @_;
    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log( Priority => 'error', Message => "Need What!" );
        return;
    }
    # module options
    my %Option = ( PreAuth => 1, );
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
    my $CustomerID = $ENV{$Self->{CustomerIDEnvVar}} || 'default_customer';
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
        'Customer::AuthModule::HTTPBasicAuth::Replace' . $Self->{Count},
    );
    if ($Replace) {
        $User =~ s/^\Q$Replace\E//;
    }
    # regexp on login
    my $ReplaceRegExp = $Kernel::OM->Get('Kernel::Config')->Get(
        'Customer::AuthModule::HTTPBasicAuth::ReplaceRegExp' . $Self->{Count},
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
    my %UserTest = $Self->{CustomerUserObject}->CustomerUserDataGet( User => $User );
    if (! %UserTest) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message  => "User '$User' doesn't have an account here yet, provisioning it now",
        );
        # Add new customer
        my $newuser = $Self->{CustomerUserObject}->CustomerUserAdd(
            Source         => 'CustomerUser',
            UserFirstname  => $FirstName,
            UserLastname   => $LastName,
            UserCustomerID => $CustomerID,
            UserLogin      => $User,
            UserPassword   => $Self->{CustomerUserObject}->GenerateRandomPassword(),
            UserEmail      => $Mail,
            ValidID        => 1,
            UserID         => 1,
         );
    }
    # return user
    return $User;
}
1;
