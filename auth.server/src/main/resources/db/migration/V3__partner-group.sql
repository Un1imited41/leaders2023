CREATE SEQUENCE sq_group_members_id AS integer START 1 OWNED BY group_members.id;

ALTER TABLE group_members ALTER COLUMN id SET DEFAULT nextval('sq_group_members_id');

ALTER TABLE group_members ADD CONSTRAINT group_members_username_group_id_unique UNIQUE (username, group_id);

insert into groups (id, group_name)
values (1, 'partner_group');

insert into group_authorities (group_id, authority)
values (1, 'partner');