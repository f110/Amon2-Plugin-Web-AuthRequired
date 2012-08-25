use strict;
use warnings;

use Test::More;
use Test::MockModule;
use Test::MockObject;

BEGIN {
    use_ok("Amon2::Plugin::Web::AuthRequired");
}

#{
    #package MyApp::Authenticator;
    #use parent qw/Class::Accessor::Fast/;
    #sub is_authenticated_user {
        #return 1;
    #}
#}
{
    package MyApp;
    use parent qw/Amon2/;
}
{
    package MyApp::Web;
    use parent -norequire, qw/MyApp/;
    use parent qw/Amon2::Web/;

    __PACKAGE__->load_plugins("Web::AuthRequired", +{
        Authenticator => "MyApp::Authenticator",
    });
}

subtest "can_ok" => sub {
    can_ok("Amon2::Plugin::Web::AuthRequired", qw/
        init
        before_dispatch
        _is_allow_access
    /);
};

subtest "path match" => sub {
    Amon2::Plugin::Web::AuthRequired->init(MyApp::Web->new(), +{
        Authenticator => "MyApp::Authenticator",
        template => "login.tt",
        rules => [
            { deny  => 'all' },
            { allow => '/login' },
        ]
    });

    is(
        Amon2::Plugin::Web::AuthRequired::_is_allow_access("/login"),
        1,
        "not required authenticate page"
    );

    is(
        Amon2::Plugin::Web::AuthRequired::_is_allow_access("/logout"),
        0,
        "required authenticate page"
    );

    Amon2::Plugin::Web::AuthRequired->init(MyApp::Web->new(), +{
        Authenticator => "MyApp::Authenticator",
        template => "login.tt",
        rules => [
            { allow => 'all' },
            { deny  => '/logout' },
        ]
    });

    is(
        Amon2::Plugin::Web::AuthRequired::_is_allow_access("/login"),
        1,
        "not required authenticate page"
    );

    is(
        Amon2::Plugin::Web::AuthRequired::_is_allow_access("/logout"),
        0,
        "required authenticate page"
    );
};

subtest "before_dispatch" => sub {
    {
        my $allow_access = 0;
        my $module = Test::MockModule->new("Amon2::Plugin::Web::AuthRequired");
        $module->mock("_is_allow_access", sub {$allow_access});

        my $mocked_authenticator = Test::MockObject->new();
        $mocked_authenticator->set_always("is_authenticated_user", 1);

        my $mocked_req = Test::MockObject->new();
        $mocked_req->set_always("path_info", 1);
        my $mocked_web = Test::MockObject->new();
        $mocked_web->set_always("req", $mocked_req);
        $mocked_web->set_always("render", 1);

        Amon2::Plugin::Web::AuthRequired->init(MyApp::Web->new(), +{
            Authenticator => $mocked_authenticator,
            template => "login.tt",
            rules => [
                { allow => 'all' },
                { deny  => '/logout' },
            ]
        });

        is(
            Amon2::Plugin::Web::AuthRequired::before_dispatch($mocked_web),
            undef,
            "is authenticated"
        );

        $mocked_authenticator->set_always("is_authenticated_user", 0);
        my $result = Amon2::Plugin::Web::AuthRequired::before_dispatch($mocked_web);
        isnt $result, undef, "is authenticated";
        $mocked_web->called_ok("render");
    }
};

done_testing();
