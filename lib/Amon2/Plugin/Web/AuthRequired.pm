package Amon2::Plugin::Web::AuthRequired;
use strict;
use warnings;
use 5.012004;
our $VERSION = '0.01';

my @rules;
my $default_match = 1;
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
            $default_match = 0;
        } else {
            $default_match = 1;
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

    my $match_result = $default_match;
    for my $rule (@rules) {
        if (index($rule->{target}, "allow") != -1
                    && $class->req->path_info =~ /$rule->{matcher}/) {
            $match_result = 0;
            next;
        }

        if (index($rule->{target}, "deny") != -1
                    && $class->req->path_info =~ /$rule->{matcher}/) {
            $match_result = 1;
            next;
        }
    }

    # Allow access
    return unless $match_result;

    return if ($authenticator->is_authenticated_user($class));

    if ($template) {
        $class->render($template);
    } else {
        $class->res_404;
    }
}

1;
__END__

=head1 NAME

Amon2::Plugin::Web::AuthRequired - Perl extension for blah blah blah

=head1 SYNOPSIS

=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Fumihiro Itoh, E<lt>fmhrit@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Fumihiro Itoh

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
