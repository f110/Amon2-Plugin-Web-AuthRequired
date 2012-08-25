package Amon2::Plugin::Web::AuthRequired;
use strict;
use warnings;
use 5.012004;
our $VERSION = '0.01';

my @rules;
my $default_match = 0;
my $template = undef;
my $authenticator = undef;
sub init {
    my ($class, $context, $conf) = @_;

    @rules = map {
        +{
            target => keys %$_,
            matcher => values %$_,
        }
    } @{$conf->{rules}};

    for my $rule (@rules) {
        next unless $rule->{matcher} eq 'all';

        if ($rule->{target} eq 'allow') {
            $default_match = 1;
        } else {
            $default_match = 0;
        }
    }

    $authenticator = $conf->{Authenticator} if exists $conf->{Authenticator};
    $template = $conf->{template} if exists $conf->{template};

    $context->add_trigger(
        BEFORE_DISPATCH => \&before_dispatch,
    );
}

sub before_dispatch {
    my ($class) = @_;

    # Allow access
    return if _is_allow_access($class->req->path_info);

    return if ($authenticator->is_authenticated_user($class));

    if ($template) {
        $class->render($template);
    } else {
        $class->res_404;
    }
}

sub _is_allow_access {
    my $path_info = shift;

    my $match_result = $default_match;
    for my $rule (@rules) {
        if (index($rule->{target}, "allow") != -1
                    && $path_info =~ /$rule->{matcher}/) {
            $match_result = 1;
            next;
        }

        if (index($rule->{target}, "deny") != -1
                    && $path_info =~ /$rule->{matcher}/) {
            $match_result = 0;
            next;
        }
    }

    return $match_result;
}

1;
__END__

=head1 NAME

Amon2::Plugin::Web::AuthRequired

=head1 SYNOPSIS

  package YourApp::Web;
  use parent qw/YourApp Amon2::Web/;
  use Amon2::Plugin::Web::AuthRequired;

  __PACKAGE__->load_plugins('Web::AuthRequired', +{
      Authenticator => YourApp::Auth::Authenticator->new(),
      template => "login.tt",
      rules = [
          {deny => 'all'},
          {allow => '/login'},
      ],
  });
  1;

  package YourApp::Auth::Authenticator;
  use List::MoreUtils qw/any/;

  my @users = qw(
      test
      foo
      bar
  );
  sub is_authenticated_user {
      my $class = shift; # $class is YourApp::Web

      return 1 if any { $class->req->session->get('username') eq $_ } @users;
      return 0;
  }

  1;

=head1 CONFIGURATION

=item Authenticator

=item template

=item rules

=head1 SEE ALSO

L<Amon2>

=head1 AUTHOR

Fumihiro Itoh, E<lt>fmhrit@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Fumihiro Itoh

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
