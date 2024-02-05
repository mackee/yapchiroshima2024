requires 'Plack';
requires 'Plack::Middleware::Session';
requires 'CBOR::PP';
requires 'Data::UUID';
requires 'CryptX';
requires 'CHI';

on 'develop' => sub {
    requires 'Data::Printer';
};
