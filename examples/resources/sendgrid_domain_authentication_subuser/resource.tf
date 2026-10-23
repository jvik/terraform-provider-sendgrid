# Let a subuser send from a domain the parent account has already
# authenticated. No new domain or DNS records are created.
data "sendgrid_domain_authentication" "parent" {
  domain    = "mycompany.com"
  subdomain = "em1234"
}

resource "sendgrid_subuser" "team" {
  username = "team-a"
  email    = "team-a@mycompany.com"
  password = var.subuser_password
  ips      = ["10.10.10.10"]
}

resource "sendgrid_domain_authentication_subuser" "team" {
  domain_id = data.sendgrid_domain_authentication.parent.id
  username  = sendgrid_subuser.team.username
}
