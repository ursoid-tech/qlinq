use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'durable transfer file storage' => sub {
    my ($stderr, $stdout) = run_prog('t/00util/test_xfer_file');
    is($stdout, "===QLINQ XFER FILE OK===\n",
       'resume, verification, atomic commit and destination safety');
};

subtest 'transfer protocol rejects invalid peer records' => sub {
    my ($stderr, $stdout) = run_prog('t/00util/test_xfer_protocol');
    is($stdout, "===QLINQ XFER PROTOCOL OK===\n",
       'malformed records, invalid offsets and false completion are rejected');
};

subtest 'qlinq-app verified resumable transfer' => sub {
    my ($stderr, $stdout) = run_prog('sh t/00util/test_qlinq_xfer.sh');
    is($stdout, "===QLINQ APP TRANSFER OK===\n",
       'large, empty, reverse, resumed and repeated transfers complete safely');
};

done_testing;
