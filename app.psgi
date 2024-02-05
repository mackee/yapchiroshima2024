use v5.38;
use utf8;
no warnings qw/experimental::try experimental::builtin/;
use feature qw/try/;
use builtin;

use Plack::Builder;
use Plack::App::File;
use Plack::Request;
use JSON::PP qw/decode_json encode_json/;
use MIME::Base64 qw/decode_base64url encode_base64url/;
use CBOR::PP;
use Data::UUID;
use Crypt::PK::ECC;
use Crypt::Digest::SHA256 qw/sha256/;
use Crypt::PRNG qw/random_string/;
use CHI;
use DDP;

my $ug = Data::UUID->new;

use constant {
    SESSION_SECRET => 'QWltALdFgFRNjZ1hcJDQ6x4iaXkbS8+IPKhH5hTCeXEHXB3JmNzv3OHuY2VRHfPn',

    COSE_KTY_KEY   => 1,
    COSE_ALG_KEY   => 3,
    COSE_CRV_KEY   => -1,
    COSE_EC2_X_KEY => -2,
    COSE_EC2_Y_KEY => -3,
    COSE_KTY_EC2   => 2,
    COSE_ALG_ES256 => -7,
    COSE_CRV_P256  => 1,

    RPID => 'localhost',
    ORIGIN => 'http://localhost:5000',

    EXCEPTION_BAD_REUQEST => "Bad Request",
};

my $datastore = CHI->new(
    driver => 'File',
    root_dir => './data',
    file_ext => '.dat',
    namespace => 'webauthn_demo',
);

builder {
    enable 'Session::Cookie',
        session_key => 'webauthn_demo_session',
        expires => 60 * 60 * 24 * 7,
        secret => SESSION_SECRET;

    mount "/" => Plack::App::File->new(file => './html/index.html')->to_app;

    mount "/register/challenge" => sub ($env) {
        my $req = Plack::Request->new($env);
        if ($req->method ne 'POST') {
            return render_json(405 => {error => 'Method Not Allowed'});
        }
        my $challenge = encode_base64url(random_string(32));
        $req->session->{challenge} = $challenge;
        my $body = decode_json($req->content);
        $req->session->{register_username} = $body->{username};
        my $user_id = encode_base64url(random_string(16));

        return render_json({challenge => $challenge, userId => $user_id, rpId => RPID});
    },

    mount "/register" => sub ($env) {
        my $req = Plack::Request->new($env);
        if ($req->method ne 'POST') {
            return render_json(405 => {error => 'Method Not Allowed'});
        }
        my $body = decode_json($req->content);
        my $id = decode_base64url($body->{id});
        my $client_data = decode_json(decode_base64url($body->{clientDataJSON}));
        my $expect_challenge = $req->session->{challenge};
        if ($client_data->{challenge} ne $expect_challenge) {
            return render_json(400 => {error => 'Bad Request'});
        }
        if ($client_data->{origin} ne ORIGIN) {
            return render_json(400 => {error => 'Bad Request'});
        }
        my $attestation_object = CBOR::PP::decode(decode_base64url($body->{attestationObject}));
        my $auth_data = $attestation_object->{authData};
        my ($rp_id_hash, $flags, $sign_count, $aaguid, $credential_id, $credential_public_key) = unpack('a32 a N a16 n/a a*', $auth_data);
        try {
            parse_cose_public_key($credential_public_key);
        } catch($e) {
            warn $e;
            return render_json(503 => {error => 'Internal Server Error'});
        }

        my $username = $req->session->{register_username};
        $datastore->set($id, encode_json({username => $username, cose => $credential_public_key}));
        delete $req->session->{challenge};
        delete $req->session->{register_username};

        return render_json({status => 'ok'});
    };

    mount "/login/challenge" => sub ($env) {
        my $req = Plack::Request->new($env);
        if ($req->method ne 'POST') {
            return render_json(405 => {error => 'Method Not Allowed'});
        }
        my $challenge = encode_base64url(random_string(32));
        $req->session->{challenge} = $challenge;

        return render_json({challenge => $challenge});
    };

    mount "/login" => sub ($env) {
        my $req = Plack::Request->new($env);
        if ($req->method ne 'POST') {
            return render_json(405 => {error => 'Method Not Allowed'});
        }
        my $body = decode_json($req->content);
        my $client_data = decode_json(decode_base64url($body->{clientDataJSON}));
        my $challenge = $client_data->{challenge};
        if ($challenge ne $req->session->{challenge}) {
            return render_json(400 => {error => 'Bad Request'});
        }
        if ($client_data->{origin} ne ORIGIN) {
            return render_json(400 => {error => 'Bad Request'});
        }
        my $authenticator_data = decode_base64url($body->{authenticatorData});
        my ($rp_id_hash, $flags, $sign_count) = unpack('a32 a N a*', $authenticator_data);
        if ($rp_id_hash ne sha256(RPID)) {
            return render_json(400 => {error => 'Bad Request'});
        }
        my $id = decode_base64url($body->{id});
        my $userdata = decode_json($datastore->get($id));
        if (!defined $userdata) {
            return render_json(400 => {error => 'Bad Request'});
        }
        my $public_key = parse_cose_public_key($userdata->{cose});
        my $sig_data = $authenticator_data . sha256(decode_base64url($body->{clientDataJSON}));
        my $signature = decode_base64url($body->{signature});
        if (!$public_key->verify_message($signature, $sig_data, "SHA256")) {
            return render_json(400 => {error => 'Bad Request'});
        }
        delete $req->session->{challenge};
        $req->session->{logged_in_username} = $userdata->{username};

        return render_json({status => 'ok'});
    };

    mount "/logout" => sub ($env) {
        my $req = Plack::Request->new($env);
        if ($req->method ne 'POST') {
            return render_json(405 => {error => 'Method Not Allowed'});
        }
        $req->session_options->{expire} = builtin::true;

        return render_json({status => 'ok'});
    };

    mount "/whoami" => sub ($env) {
        my $req = Plack::Request->new($env);
        my $session = $req->session;
        if (!exists $session->{logged_in_username}) {
            return render_json({logged_in => builtin::false});
        }
        return render_json({username => $session->{logged_in_username}, logged_in => builtin::true});
    }
};

sub parse_cose_public_key($public_key) {
    my $cose = CBOR::PP::decode($public_key);
    if ($cose->{COSE_KTY_KEY()} != COSE_KTY_EC2) {
        die EXCEPTION_BAD_REUQEST;
    }
    if ($cose->{COSE_ALG_KEY()} != COSE_ALG_ES256) {
        die EXCEPTION_BAD_REUQEST;
    }
    my $pk = Crypt::PK::ECC->new();
    my $curve;
    if ($cose->{COSE_CRV_KEY()} == COSE_CRV_P256) {
        $curve = 'secp256r1';
    } else {
        die EXCEPTION_BAD_REUQEST;
    }

    $pk->import_key({
        kty => 'EC',
        crv => $curve,
        x   => encode_base64url($cose->{COSE_EC2_X_KEY()}),
        y   => encode_base64url($cose->{COSE_EC2_Y_KEY()}),
    });
}

sub render_json($data, @args) {
    my $code = 200;
    if (ref $data ne 'HASH') {
        $code = $data;
        $data = $args[0];
    }
    return [$code, ["content-type" => "application/json"], [encode_json($data)]];
}
