use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'BBR command-line selection' => sub {
    for my $program ('qlinq-app', 'qlinqd', 'qlinq-tun') {
        my ($stderr, $stdout) = run_prog("./$program --cc bbr --help");
        like($stdout, qr/--cc[^\n]*bbr/, "$program accepts and documents BBR")
            or diag($stderr);
    }
};

subtest 'qlinq-app direct transport API' => sub {
    my ($stderr, $stdout) = run_prog('sh t/00util/test_qlinq_app.sh');
    is($stdout, "===QLINQ APP DIRECT API OK===\n",
       'rateless file transfer uses the in-process transport API');
};

subtest 'idle path probe command-line option' => sub {
    for my $program ('qlinq-app', 'qlinqd', 'qlinq-tun') {
        for my $interval (0, 500, 4294967295) {
            my ($stderr, $stdout) = run_prog("./$program --path-probe-ms $interval --help");
            like($stdout, qr/--path-probe-ms/, "$program accepts $interval ms")
                or diag($stderr);
        }
        for my $interval ('-1', '4294967296', 'no') {
            my $output = `./$program --path-probe-ms $interval --help 2>&1`;
            isnt($?, 0, "$program rejects $interval ms") or diag($output);
        }
    }
};

done_testing;
