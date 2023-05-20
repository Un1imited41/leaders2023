create table if not exists users
(
    username varchar(255) not null primary key,
    password varchar(255) not null,
    enabled  boolean      not null
);

create table if not exists authorities
(
    username  varchar(255) not null,
    authority varchar(255) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index if not exists ix_auth_username on authorities (username, authority);


create table if not exists groups
(
    id         bigint primary key,
    group_name varchar(255) not null
);

create table if not exists group_authorities
(
    group_id  bigint       not null,
    authority varchar(255) not null,
    constraint fk_group_authorities_group foreign key (group_id) references groups (id)
);

create table if not exists group_members
(
    id       bigint primary key,
    username varchar(255) not null,
    group_id bigint       not null,
    constraint fk_group_members_group foreign key (group_id) references groups (id)
);

create table if not exists oauth2_authorization_consent
(
    registered_client_id varchar(255) not null,
    principal_name       varchar(255) not null,
    authorities          varchar(255) not null,
    constraint pk_oauth2_authorization_consent unique (registered_client_id, principal_name)
);

CREATE TABLE if not exists oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    PRIMARY KEY (id)
);