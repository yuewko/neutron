use nuage_neutron;

delimiter //

create procedure IB_UpgradeNuageNeutron()
begin

    --
    -- Table structure for table `infoblox_mgmt_net_ips`
    --
    drop table if exists `infoblox_mgmt_net_ips`;
    create table `infoblox_mgmt_net_ips` (
      `network_id` varchar(255) NOT NULL,
      `ip_address` varchar(64) NOT NULL,
      `fixed_address_ref` varchar(255) NOT NULL,
      primary key (`network_id`)
    ) engine=innodb default charset=utf8;

    --
    -- Table structure for table `infoblox_net_views`
    --
    drop table if exists `infoblox_net_views`;
    create table `infoblox_net_views` (
      `network_id` varchar(36) NOT NULL,
      `network_view` varchar(56) DEFAULT NULL,
      primary key (`network_id`),
      constraint `infoblox_net_views_ibfk_1` foreign key (`network_id`) references `networks` (`id`) on delete cascade
    ) engine=innodb default charset=utf8;

    --
    -- Table structure for table `infoblox_member_maps`
    --
    drop table if exists `infoblox_member_maps`;
    create table `infoblox_member_maps` (
      `member_name` varchar(255) NOT NULL,
      `map_id` varchar(255) NOT NULL,
      `member_type` varchar(10) DEFAULT NULL
    ) engine=innodb default charset=utf8;

    --
    -- Table structure for table `infoblox_dhcp_members`
    --
    drop table if exists `infoblox_dhcp_members`;
    create table `infoblox_dhcp_members` (
      `id` varchar(36) NOT NULL,
      `network_id` varchar(36) NOT NULL,
      `server_ip` varchar(40) NOT NULL,
      `server_ipv6` varchar(40) NOT NULL,
      primary key (`id`),
      key `network_id` (`network_id`),
      constraint `infoblox_dhcp_members_ibfk_1` foreign key (`network_id`) references `networks` (`id`) on delete cascade
    ) engine=innodb default charset=utf8;

    --
    -- Table structure for table `infoblox_dns_members`
    --
    drop table if exists `infoblox_dns_members`;
    create table `infoblox_dns_members` (
      `id` varchar(36) NOT NULL,
      `network_id` varchar(36) NOT NULL,
      `server_ip` varchar(40) NOT NULL,
      `server_ipv6` varchar(40) NOT NULL,
      primary key (`id`),
      key `network_id` (`network_id`),
      constraint `infoblox_dns_members_ibfk_1` foreign key (`network_id`) references `networks` (`id`) on delete cascade
    ) engine=innodb default charset=utf8;

end; //

delimiter ;
 
call IB_UpgradeNuageNeutron();

drop procedure IB_UpgradeNuageNeutron;

