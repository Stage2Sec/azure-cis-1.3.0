policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "azure-cis-section-1" {
    description = "Azure CIS Section 1"

    query "1.1" {
      description   = "Azure CIS 1.1 Ensure that multi-factor authentication is enabled for all privileged users (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Enable multi-factor authentication for all user credentials who have write access to Azure resources. These include roles like:\n\n- Service Co-Administrators\n- Subscription Owners\n- Contributors\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n\n**Note:** By default, multi-factor authentication is disabled for all users.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `All Users`\n4. Click on **Multi-Factor Authentication** button on the top bar\n5. Ensure that **MULTI-FACTOR AUTH STATUS** is `Enabled` for all users who are `Service Co-Administrators` OR `Owners` OR `Contributors`.\n\nTo enable MFA, follow Microsoft Azure [documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa) and setup multi-factor authentication in your environment.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_1"
        source          = "mage"
        summary         = "Enable multi-factor authentication for all user credentials who have write access to Azure resources. These include roles like:\n\n- Service Co-Administrators\n- Subscription Owners\n- Contributors\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n\n**Note:** By default, multi-factor authentication is disabled for all users.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "1.2" {
      description   = "Azure CIS 1.2 Ensure that multi-factor authentication is enabled for all non-privileged users (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Enable multi-factor authentication for all non-privileged users.\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n\n**Note:** By default, multi-factor authentication is disabled for all users.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `All Users`\n4. Click on **Multi-Factor Authentication** button on the top bar\n5. Ensure that **MULTI-FACTOR AUTH STATUS** is `Enabled` for all users\n\nTo enable MFA\n\nFollow Microsoft Azure [documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa) and setup multi-factor authentication in your environment.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_2"
        source          = "mage"
        summary         = "Enable multi-factor authentication for all non-privileged users.\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n\n**Note:** By default, multi-factor authentication is disabled for all users.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "1.3" {
      description   = "Azure CIS 1.3 Ensure guest users are reviewed on a monthly basis (Automated)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Azure AD is extended to include Azure AD B2B collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account and sign in with their own work, school, or social identities. Guest users allow you to share your company's applications and services with users from any other organization, while maintaining control over your own corporate data. Work with external partners, large or small, even if they don't have Azure AD or an IT department. A simple invitation and redemption process lets partners use their own credentials to access your company's resources a guest user.\n\nGuest users in the Azure AD are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants, Guest users should be reviewed on a regular basis, at least annually, Guest users should not be granted administrative roles where possible.\n\nGuest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely leading to a potential vulnerability. Guest users should be review on a monthly basis to ensure that inactive and unneeded accounts are removed.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users` and `Groups`\n3. Go to `All Users`\n4. Click on **Show** drop down and select `Guest users` only\n5. Delete all `Guest` users that are no longer required or are inactive.\n\nIt is good practice to use a dynamic group to manage guest users. To create the dynamic group:\n\n1. Navigate to the `Active Directory` blade in the Azure Portal\n2. Select the `Groups` item\n3. Create `new`\n4. Type of `dynamic`\n5. Use the following dynamic selection rule. \"(user.userType -eq \"Guest\")\"\n6. Once the group has been created, select access reviews option and create a new access review with a period of monthly and send to relevant administrators for review.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_3"
        source          = "mage"
        summary         = "Azure AD is extended to include Azure AD B2B collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account and sign in with their own work, school, or social identities. Guest users allow you to share your company's applications and services with users from any other organization, while maintaining control over your own corporate data. Work with external partners, large or small, even if they don't have Azure AD or an IT department. A simple invitation and redemption process lets partners use their own credentials to access your company's resources a guest user.\n\nGuest users in the Azure AD are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants, Guest users should be reviewed on a regular basis, at least annually, Guest users should not be granted administrative roles where possible.\n\nGuest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely leading to a potential vulnerability. Guest users should be review on a monthly basis to ensure that inactive and unneeded accounts are removed.\n"
      }
    }

    query "1.4" {
      description   = "Azure CIS 1.4 Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is 'Disabled' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Do not allow users to remember multi-factor authentication on devices.\n\nRemembering Multi-Factor Authentication(MFA) for devices and browsers allows users to have the option to by-pass MFA for a set number of days after performing a successful signin using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `All Users`\n4. Click on **Multi-Factor Authentication** button on the top bar5.\n5. Click on **service settings**\n6. Ensure that `Allow users to remember multi-factor authentication on devices they trust` is not `enabled`\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_4"
        source          = "mage"
        summary         = "Do not allow users to remember multi-factor authentication on devices.\n\nRemembering Multi-Factor Authentication(MFA) for devices and browsers allows users to have the option to by-pass MFA for a set number of days after performing a successful signin using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "1.5" {
      description   = "Azure CIS 1.5 Ensure that 'Number of methods required to reset' is set to '2' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `Password reset` in side bar\n4. Go to `Authentication methods` in side bar\n5. Set the `Number of methods required to reset` to **2**\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_5"
        source          = "mage"
        summary         = "Ensure that two alternate forms of identification are provided before allowing a password reset.\n\nLike multi-factor authentication, setting up dual identification before allowing a password reset ensures that the user identity is confirmed via two separate forms of identification. With dual identification set, an attacker would require compromising both the identity forms before he/she could maliciously reset a user's password.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Ensure that two alternate forms of identification are provided before allowing a password reset.\n\nLike multi-factor authentication, setting up dual identification before allowing a password reset ensures that the user identity is confirmed via two separate forms of identification. With dual identification set, an attacker would require compromising both the identity forms before he/she could maliciously reset a user's password.\n"
      }
    }

    query "1.6" {
      description   = "Azure CIS 1.6 Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to \"0\" (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_6"
        source          = "mage"
        summary         = "Ensure that the number of days before users are asked to re-confirm their authentication information is not set to 0.\n\nIf authentication re-confirmation is disabled, registered users will never be prompted to reconfirm their existing authentication information. If the authentication information for a user, such as a phone number or email changes, then the password reset information for that user reverts to the previously registered authentication information.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Ensure that the number of days before users are asked to re-confirm their authentication information is not set to 0.\n\nIf authentication re-confirmation is disabled, registered users will never be prompted to reconfirm their existing authentication information. If the authentication information for a user, such as a phone number or email changes, then the password reset information for that user reverts to the previously registered authentication information.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `Password reset` in side bar\n4. Go to `Registration`\n5. Set the `Number of days before users are asked to re-confirm their authentication information` to your organization defined frequency\n\n**Note:** By default, the 'Number of days before users are asked to re-confirm their authentication information' is set to '180 days'.\n"
      }
    }


    query "1.7" {
      description   = "Azure CIS 1.7 Ensure that 'Notify users on password resets?' is set to 'Yes' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Ensure that users are notified on their primary and secondary emails on password resets.\n\nUser notification on password reset is a passive way of confirming password reset activity. It helps the user to recognize unauthorized password reset activities.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `Password reset` in side bar\n4. Go to `Notification`\n5. Ensure that `Notify users on password resets`? is set to **Yes**\n\n**Note:** By default, 'Notify users on password resets?' is set to 'Yes'.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_7"
        source          = "mage"
        summary         = "Ensure that users are notified on their primary and secondary emails on password resets.\n\nUser notification on password reset is a passive way of confirming password reset activity. It helps the user to recognize unauthorized password reset activities.\n"
      }
    }


    query "1.8" {
      description   = "Azure CIS 1.8 Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Ensure that all administrators are notified if any other administrator resets their password.\n\nAdministrator accounts are sensitive. Any password reset activity notification, when sent to all administrators, ensures that all administrators can passively confirm if such a reset is a common pattern within their group. For example, if all administrators change their password every 30 days, any password reset activity before that may require administrator(s) to evaluate any unusual activity and confirm its origin.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `Password reset` in side bar\n4. Go to `Notification`\n5. Set `Notify all admins when other admins reset their password?` to **Yes**\n\n**Note:** By default, `Notify all admins when other admins reset their password?` is set to 'Yes'.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_8"
        source          = "mage"
        summary         = "Ensure that all administrators are notified if any other administrator resets their password.\n\nAdministrator accounts are sensitive. Any password reset activity notification, when sent to all administrators, ensures that all administrators can passively confirm if such a reset is a common pattern within their group. For example, if all administrators change their password every 30 days, any password reset activity before that may require administrator(s) to evaluate any unusual activity and confirm its origin.\n"
      }
    }

    query "1.9" {
      description   = "Azure CIS 1.9 Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Require administrators to provide consent for the apps before use.\n\nUnless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of the cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `User settings` in side bar\n4. Click on **Manage how end users launch and view their applications**\n5. Set `Users can consent to apps accessing company data on their behalf` to **No**\n\n**Note:** By default, `Users can consent to apps accessing company data on their behalf` is set to 'Yes'.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_9"
        source          = "mage"
        summary         = "Require administrators to provide consent for the apps before use.\n\nUnless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of the cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "1.10" {
      description   = "Azure CIS 1.10 Ensure that 'Users can add gallery apps to their Access Panel' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        summary         = "Require administrators to provide consent for the apps before use.\n\nUnless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of the cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Require administrators to provide consent for the apps before use.\n\nUnless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of the cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `User settings` in side bar\n4. Click on `Manage how end users launch and view their applications`\n5. Set `Users can add gallery apps to their Access Panel` to **No**\n\n**Note:** By default, `Users can add gallery apps to their Access Panel` is set to 'No'.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_10"
        source          = "mage"
      }
    }


    query "1.11" {
      description   = "Azure CIS 1.11 Ensure that 'Users can register applications' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        source          = "mage"
        summary         = "Require administrators to register third-party applications.\n\nIt is recommended to let administrator register custom-developed applications. This ensures that the application undergoes a security review before exposing active directory data to it.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Require administrators to register third-party applications.\n\nIt is recommended to let administrator register custom-developed applications. This ensures that the application undergoes a security review before exposing active directory data to it.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `User settings` in side bar\n4. Set `Users can register applications` to **No**\n\n**Note:** By default, `Users can add gallery apps to their Access Panel` is set to 'No'.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_11"
      }
    }


    query "1.12" {
      description   = "Azure CIS 1.12 Ensure that 'Guest user permissions are limited' is set to 'Yes' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Limit guest user permissions.\n\nLimiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. If guest access in not limited, they have the same access to directory data as regular users.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `External Identities` in side bar\n3. Go to `External collaboration settings` further from side bar\n4. Set Guest users permissions to limited as per organization policy.\n\nSee more details [here](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#member-and-guest-users)\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_12"
        source          = "mage"
        summary         = "Limit guest user permissions.\n\nLimiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. If guest access in not limited, they have the same access to directory data as regular users.\n"
      }
    }

    query "1.13" {
      description   = "Azure CIS 1.13 Ensure that 'Members can invite' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        source          = "mage"
        summary         = "Restrict invitations to administrators only.\n\nRestricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain `Need to Know` permissions and prevents inadvertent access to data.\n\nBy default the setting Admins and users in the guest inviter role can invite is set to yes. This will allow you to use the inviter role to control who will be able to invite guests to the tenant.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restrict invitations to administrators only.\n\nRestricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain `Need to Know` permissions and prevents inadvertent access to data.\n\nBy default the setting Admins and users in the guest inviter role can invite is set to yes. This will allow you to use the inviter role to control who will be able to invite guests to the tenant.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `External Identities`\n3. Go to `External collaboration settings`\n4. Restrict `Guest invite restrictions` to `Only users assigned to specific admin roles can invite guest users`\n\n**Note:** By default, Members can invite is set to `Yes`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_13"
      }
    }

    query "1.14" {
      description   = "Azure CIS 1.14 Ensure that 'Guests can invite' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_14"
        source          = "mage"
        summary         = "Restrict guest being able to invite other guests to collaborate with your organization.\n\nRestricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain \"Need to Know\" permissions and prevents inadvertent access to data.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restrict guest being able to invite other guests to collaborate with your organization.\n\nRestricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain \"Need to Know\" permissions and prevents inadvertent access to data.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `External Identities`\n3. Go to `External collaboration settings`\n4. Ensure that Guests can invite is set to **No**\n\n**Note:** By default, Guests can invite is set to `Yes`.\n"
      }
    }

    query "1.15" {
      description   = "Azure CIS 1.15 Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        source          = "mage"
        summary         = "Restrict access to the Azure AD administration portal to administrators only.\n\nThe Azure AD administrative portal has sensitive data. All non-administrators should be prohibited from accessing any Azure AD data in the administration portal to avoid exposure.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restrict access to the Azure AD administration portal to administrators only.\n\nThe Azure AD administrative portal has sensitive data. All non-administrators should be prohibited from accessing any Azure AD data in the administration portal to avoid exposure.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Users`\n3. Go to `User settings`\n4. Set `Restrict access to Azure AD administration portal` to **Yes**\n\n**Note:** By default, Restrict access to Azure AD administration portal is set to `No`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_15"
      }
    }


    query "1.16" {
      description   = "Azure CIS 1.16 Ensure that 'Restrict user ability to access groups features in the Access Pane' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        source          = "mage"
        summary         = "Restrict group creation to administrators only.\n\nSelf-service group management enables users to create and manage security groups or Office 365 groups in Azure Active Directory (Azure AD). Unless a business requires this day-to-day delegation for some users, self-service group management should be disabled.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restrict group creation to administrators only.\n\nSelf-service group management enables users to create and manage security groups or Office 365 groups in Azure Active Directory (Azure AD). Unless a business requires this day-to-day delegation for some users, self-service group management should be disabled.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Groups`\n3. Go to `General` in setting section\n4. Ensure that `Restrict user ability to access groups features` in the Access Pane is set to **No**\n\n**Note:** By default, Restrict user ability to access groups features in the Access Pane is set to No.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_16"
      }
    }


    query "1.17" {
      description   = "Azure CIS 1.17 Ensure that 'Users can create security groups in Azure Portals' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Restrict security group creation to administrators only.\n\nWhen creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Groups`\n3. Go to `General` in setting section\n4. Set `Users can create security groups in Azure portals, API or PowerShell` to **No**\n\n**Note:** By default, Users can create security groups is set to Yes.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_17"
        source          = "mage"
        summary         = "Restrict security group creation to administrators only.\n\nWhen creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "1.18" {
      description   = "Azure CIS 1.18 Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restrict security group management to administrators only.\n\nRestricting security group management to administrators only prohibits users from making changes to security groups. This ensures that security groups are appropriately managed and their management is not delegated to non-administrators.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Groups`\n3. Go to `General` in setting section\n4. Ensure that `Owners can manage group membership requests in the Access Panel` is set to **No**\n\n**Note:** By default, `Owners can manage group membership requests in the Access Panel` is set to `No`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_18"
        source          = "mage"
        summary         = "Restrict security group management to administrators only.\n\nRestricting security group management to administrators only prohibits users from making changes to security groups. This ensures that security groups are appropriately managed and their management is not delegated to non-administrators.\n"
      }
    }

    query "1.19" {
      description   = "Azure CIS 1.19 Ensure that 'Users can create Microsoft 365 groups in Azure Portals' is set to 'No' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Restrict Microsoft 365 group creation to administrators only.\n\nRestricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user.\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Groups`\n3. Go to `General` in setting section\n4. Set `Users can create Microsoft 365 groups in Azure Portals` to **No**\n\n**Note:** By default, `Users can create Microsoft 365 groups in Azure Portals` is set to `Yes`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_19"
        source          = "mage"
        summary         = "Restrict Microsoft 365 group creation to administrators only.\n\nRestricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }


    query "1.20" {
      description   = "Azure CIS 1.20 Ensure that 'Require Multi-Factor Auth to join devices' is set to 'Yes' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        summary         = "Joining devices to the active directory should require Multi-factor authentication.\n\nMulti-factor authentication is recommended when adding devices to Azure AD. When set to `Yes`, users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the directory for a compromised user account\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Joining devices to the active directory should require Multi-factor authentication.\n\nMulti-factor authentication is recommended when adding devices to Azure AD. When set to `Yes`, users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the directory for a compromised user account\n"
        recommendations = "### From Console\n\n1. Log in to [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)\n2. Go to `Devices` in left bar\n3. Go to `Device settings` in left bar\n4. Set `Devices to be Azure AD joined or Azure AD registered require Multi-Factor Authentication` to **Yes**\n\n**Note:** By default, `Devices to be Azure AD joined or Azure AD registered require Multi-Factor Authentication` is set to `No`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_20"
        source          = "mage"
      }
    }


    query "1.21" {
      description = "Azure CIS 1.21 Ensure that no custom subscription owner roles are created (Automated)"
      query       = <<EOF
        --check if definition matches scopes
        WITH assignable_scopes AS (SELECT cq_id, UNNEST(assignable_scopes) AS assignable_scope
        FROM azure_authorization_role_definitions v ), meets_scopes AS (SELECT cq_id
        FROM assignable_scopes a
        WHERE a.assignable_scope = '/'
        OR a.assignable_scope = 'subscription'
        GROUP BY cq_id),
        --check if definition matches actions
        definition_actions AS (SELECT role_definition_cq_id AS cq_id, UNNEST(actions) AS ACTION
        FROM azure_authorization_role_definition_permissions), meets_actions AS (SELECT cq_id
        FROM definition_actions
        WHERE "action" = '*') SELECT d.subscription_id , d.id AS definition_id, d."name" AS definition_name
        FROM azure_authorization_role_definitions d
        JOIN meets_actions a ON
        d.cq_id = a.cq_id
        JOIN meets_scopes s ON
        a.cq_id = s.cq_id
    EOF
      risk {
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_21"
        source          = "mage"
        summary         = "Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.\n\nClassic subscription admin roles offer basic access management and include Account `Administrator`, `Service Administrator`, and `Co-Administrators`. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.\n\nClassic subscription admin roles offer basic access management and include Account `Administrator`, `Service Administrator`, and `Co-Administrators`. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended.\n"
        recommendations = "### From Command Line\n\n1. Execute to get the list of role definitions to check for entries with assignableScope of / or a subscription, and an action of * Verify the usage and impact of removing the role identified\n\n```bash\naz role definition list\n```\n\n2. Review output for each returned role's 'AssignableScopes' value for '/' or the current subscription, and 'Actions' containing the '*' wildcard character. Based on the findings delete the role.\n\n```bash\naz role definition delete --name \"rolename\"\n```\n"
      }
    }

    query "1.22" {
      description   = "Azure CIS 1.22 Ensure Security Defaults is enabled on Azure Active Directory (Automated)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks.\n\nMicrosoft is making security defaults available to everyone. The goal is to ensure that all organizations have a basic level of security-enabled at no extra cost. You turn on security defaults in the Azure portal.\n\nSecurity defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.\n\nFor example doing the following:\n  - Requiring all users and admins to register for MFA.\n  - Challenging users with MFA - mostly when they show up on a new device or app, but more often for critical roles and tasks.\n  - Disabling authentication from legacy authentication clients, which can’t do MFA.\n"
        recommendations = "### From Console\n\n1. Sign in to the\u202fAzure portal\u202fas a security administrator, Conditional Access administrator, or global administrator.\n2. Browse to\u202f`Azure Active Directory`\u202f> `Properties` in side bar\n3. Select **Manage security defaults** section\n4. Set the `Enable security defaults toggle` to **Yes**.\n5. Select **Save**.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_22"
        source          = "mage"
        summary         = "Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks.\n\nMicrosoft is making security defaults available to everyone. The goal is to ensure that all organizations have a basic level of security-enabled at no extra cost. You turn on security defaults in the Azure portal.\n\nSecurity defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.\n\nFor example doing the following:\n  - Requiring all users and admins to register for MFA.\n  - Challenging users with MFA - mostly when they show up on a new device or app, but more often for critical roles and tasks.\n  - Disabling authentication from legacy authentication clients, which can’t do MFA.\n"
      }
    }

    query "1.23" {
      description   = "Azure CIS 1.23 Ensure Custom Role is assigned for Administering Resource Locks (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        recommendations = "### From Console\n\n1. In the Azure portal, open a subscription or resource group where you want the custom role to be assignable.\n2. Select `Access control (IAM)` from side bar\n3. Click `Add` from top bar\n4. Select **Add custom role**\n5. In the Custom Role Name field enter `Resource Lock Administrator`\n6. In the Description field enter Can `Administer Resource Lock`s\n7. For Baseline permissions select **Start from scratch**\n8. Click `next`\n9. In the **Permissions** tab select **Add permissions**\n10. in the Search for a permission box, type in `Microsoft.Authorization/locks` to search for permissions.\n11. Select the check box next to the permission called `Microsoft.Authorization/locks`\n12. click **add**\n13. Click **Review+create**\n14. Click **Create**\n15. Assign the newly created role to the appropriate user.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_1_23"
        source          = "mage"
        summary         = "Resource locking is a powerful protection mechanism that can prevent inadvertent modification/deletion of resources within Azure subscriptions/Resource Groups and is a recommended NIST configuration.\n\nGiven the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Resource locking is a powerful protection mechanism that can prevent inadvertent modification/deletion of resources within Azure subscriptions/Resource Groups and is a recommended NIST configuration.\n\nGiven the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources.\n"
      }
    }
  }

  policy "azure-cis-section-2" {
    description = "Azure CIS Section 2"

    view "azure_security_policy_parameters" {
      description = "GCP Log Metric Filter and Alarm"
      query "azure_security_policy_parameters" {
        query = file("queries/policy_assignment_parameters.sql")
      }
    }

    query "2.1" {
      description   = "Azure CIS 2.1 Ensure that Azure Defender is set to On for Servers (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'VirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Server, provides threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Servers:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Servers` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Servers:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Servers` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for servers\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/VirtualMachines?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ VirtualMachines\",\n  \"name\":\"VirtualMachines\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_1"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Server, provides threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "2.2" {
      description   = "Azure CIS 2.2 Ensure that Azure Defender is set to On for App Service (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'AppServices'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for App Service, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for App Service:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `App Service` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for App Service:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `App Service` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for App Service\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/AppServices?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ AppServices\",\n  \"name\":\"AppServices\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_2"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for App Service, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
      }
    }

    query "2.3" {
      description   = "Azure CIS 2.3 Ensure that Azure Defender is set to On for Azure SQL database servers (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlServers'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Azure SQL database servers, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in- depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Azure SQL database servers, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in- depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Azure SQL database servers:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Azure SQL database servers` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Azure SQL database servers:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Azure SQL database servers` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for Azure SQL database servers\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/SqlServers?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ SqlServers\",\n  \"name\":\"SqlServers\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_3"
      }
    }

    query "2.4" {
      description   = "Azure CIS 2.4 Ensure that Azure Defender is set to On for SQL servers on machines (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlserverVirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for SQL Servers on machines:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `SQL Servers on machines` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for SQL Servers on machines:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `SQL Servers on machines` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for SQL Servers on machines\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/StorageAccounts?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ StorageAccounts\",\n  \"name\":\"StorageAccounts\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"SqlserverVirtualMachines\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_4"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for SQL servers on machines, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. Enabling it allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for SQL servers on machines, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. Enabling it allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
      }
    }


    query "2.5" {
      description   = "Azure CIS 2.5 Ensure that Azure Defender is set to On for Storage (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'StorageAccounts'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Storage, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\nIt also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Storage:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Storage` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Storage:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Storage` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for Storage\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/StorageAccounts?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ StorageAccounts\",\n  \"name\":\"StorageAccounts\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_5"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Storage, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\nIt also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
      }
    }

    query "2.6" {
      description   = "Azure CIS 2.6 Ensure that Azure Defender is set to On for Kubernetes (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KubernetesService'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Kubernetes, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Kubernetes, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Kubernetes:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Kubernetes` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Kubernetes:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Kubernetes` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for Kubernetes\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/StorageAccounts?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ StorageAccounts\",\n  \"name\":\"KubernetesService\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_6"
      }
    }

    query "2.7" {
      description   = "Azure CIS 2.7 Ensure that Azure Defender is set to On for Container Registries (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'ContainerRegistry'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Container Registries:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Container Registries` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Container Registries:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Container Registries` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for Container Registries\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/StorageAccounts?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ StorageAccounts\",\n  \"name\":\"ContainerRegistry\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_7"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Container Registries, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Container Registries, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center. It also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
      }
    }

    query "2.8" {
      description   = "Azure CIS 2.8 Ensure that Azure Defender is set to On for Key Vault (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KeyVaults'
        AND pricing_properties_tier = 'Standard';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enabling Azure Defender threat detection for Key Vault, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\nIt also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Key Vault:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Key Vault` resource type `Plan` should be set to **On**.\n\nPerform the following action to enable Azure Defender for Key Vault:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, `Azure Defender plans` blade got selected.\n4. For the `Key Vault` resource type `Plan` set it to **On**.\n\n### From Command Line\n\nCommand to enable Azure defender for Key Vault\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pr icings/StorageAccounts?api-version=2018-06-01 -d@\"input.json\"'\n```\n\nWhere `input.json` contains the request body json data as mentioned below\n\n```json\n{\n  \"id\":\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/ StorageAccounts\",\n  \"name\":\"KeyVaults\",\n  \"type\":\"Microsoft.Security/pricings\",\n  \"properties\":{\n    \"pricingTier\":\"Standard\"\n  }\n}\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_8"
        source          = "mage"
        summary         = "Enabling Azure Defender threat detection for Key Vault, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.\nIt also allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n"
      }
    }

    query "2.9" {
      description   = "Azure CIS 2.9 Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'WDATP'
        AND enabled = TRUE;
    EOF
      risk {
        summary         = "This setting enables Windows Defender ATP (WDATP) integration with Security Center. WDATP integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within security center. This integration helps to spot abnormalities, detect and respond to advanced attacks on Windows server endpoints monitored by Azure Security Center.\n\nWindows Defender ATP in Security Center supports detection on Windows Server 2016, 2012 R2, and 2008 R2 SP1 operating systems in a Standard service subscription. WDATP works only with Standard Tier subscriptions.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "This setting enables Windows Defender ATP (WDATP) integration with Security Center. WDATP integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within security center. This integration helps to spot abnormalities, detect and respond to advanced attacks on Windows server endpoints monitored by Azure Security Center.\n\nWindows Defender ATP in Security Center supports detection on Windows Server 2016, 2012 R2, and 2008 R2 SP1 operating systems in a Standard service subscription. WDATP works only with Standard Tier subscriptions.\n"
        recommendations = "### From Console\n\nPerform the following action to check Azure Defender is set to On for Key Vault:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Threat Detection`.\n4. Ensure setting `Allow Microsoft Defender ATP to access my data` is selected.\n\nPerform the following action to enable Azure Defender for Key Vault:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Threat Detection`.\n4. Select `Allow Microsoft Defender ATP to access my data`.\n5. Click **Save**.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_9"
        source          = "mage"
      }
    }

    query "2.10" {
      description   = "Azure CIS 2.10 Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected (Manual)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'MCAS'
        AND enabled = TRUE;
    EOF
      risk {
        recommendations = "### From Console\n\nPerform the following action to check Defender for Endpoint to access my data is enabled:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Threat Detection`.\n4. Ensure setting `Allow Microsoft Cloud App Security to access my data` is selected.\n\nPerform the following action to enable Defender for Endpoint to access my data:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Threat Detection`.\n4. Select `Allow Microsoft Cloud App Security to access my data`.\n5. Click **Save**.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_10"
        source          = "mage"
        summary         = "This setting enables Microsoft Cloud App Security (MCAS) integration with Security Center. Security Center offers an additional layer of protection by using Azure Resource Manager events, which is considered to be the control plane for Azure.\n\nBy analyzing the Azure Resource Manager records, Security Center detects unusual or potentially harmful operations in the Azure subscription environment. Several of the preceding analytics are powered by Microsoft Cloud App Security. To benefit from these analytics, subscription must have a Cloud App Security license. MCAS works only with Standard Tier subscriptions.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "This setting enables Microsoft Cloud App Security (MCAS) integration with Security Center. Security Center offers an additional layer of protection by using Azure Resource Manager events, which is considered to be the control plane for Azure.\n\nBy analyzing the Azure Resource Manager records, Security Center detects unusual or potentially harmful operations in the Azure subscription environment. Several of the preceding analytics are powered by Microsoft Cloud App Security. To benefit from these analytics, subscription must have a Cloud App Security license. MCAS works only with Standard Tier subscriptions.\n"
      }
    }

    query "2.11" {
      description   = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
      risk {
        description     = "Enable automatic provisioning of the monitoring agent to collect security data. When this agent is turned on, Azure Security Center provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created.\n\nThe Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.\n"
        recommendations = "### From Console\n\nPerform the following action to check Defender for Endpoint to access my data is enabled:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Auto provisioning`.\n4. Ensure `Enable all extensions` is On.\n\nPerform the following action to enable Defender for Endpoint to access my data:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Auto provisioning`.\n4. Click on `Enable all extensions`.\n5. Click **Save**.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_11"
        source          = "mage"
        summary         = "Enable automatic provisioning of the monitoring agent to collect security data. When this agent is turned on, Azure Security Center provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created.\n\nThe Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "2.11" {
      description   = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enable automatic provisioning of the monitoring agent to collect security data. When this agent is turned on, Azure Security Center provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created.\n\nThe Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.\n"
        recommendations = "### From Console\n\nPerform the following action to check Defender for Endpoint to access my data is enabled:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Auto provisioning`.\n4. Ensure `Enable all extensions` is On.\n\nPerform the following action to enable Defender for Endpoint to access my data:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the subscription name, select `Auto provisioning`.\n4. Click on `Enable all extensions`.\n5. Click **Save**.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_11"
        source          = "mage"
        summary         = "Enable automatic provisioning of the monitoring agent to collect security data. When this agent is turned on, Azure Security Center provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created.\n\nThe Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.\n"
      }
    }

    query "2.12" {
      description = "Azure CIS 2.12 Ensure any of the ASC Default policy setting is not set to \"Disabled\" (Manual)"
      query       = <<EOF
        SELECT *
        FROM azure_security_policy_parameters
        WHERE value = 'Disabled';
    EOF
      risk {
        source          = "mage"
        summary         = "None of the settings offered by ASC Default policy should be set to effect *Disabled*. A security policy defines the desired configuration of your workloads and helps ensure compliance with company or regulatory security requirements. ASC Default policy is associated with every subscription by default. ASC default policy assignment is set of security recommendations based on best practices.\n\nEnabling recommendations in ASC default policy ensures that Azure security center provides ability to monitor all of the supported recommendations and allow automated action optionally for few of the supported recommendations.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "None of the settings offered by ASC Default policy should be set to effect *Disabled*. A security policy defines the desired configuration of your workloads and helps ensure compliance with company or regulatory security requirements. ASC Default policy is associated with every subscription by default. ASC default policy assignment is set of security recommendations based on best practices.\n\nEnabling recommendations in ASC default policy ensures that Azure security center provides ability to monitor all of the supported recommendations and allow automated action optionally for few of the supported recommendations.\n"
        recommendations = "### From Console\n\nPerform the following action to check ASC Default policy is set to enabled:\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Security policy` blade under Management.\n3. Click on the subscription name,\n4. Expand All the available sections.\n5. Ensure that any of the setting is not set to **Disabled**.\n\nPerform the following action to enable ASC Default policies:\n\n1. Navigate to Azure `Policy`.\n2. On Policy `Overview` tab, click on Policy `ASC Default`.\n3. On ASC Default blade, click on `Edit Assignments`.\n4. In section `Parameters`, configure the impacted setting to any other available value than `Disabled` or `empty`.\n5. Click **Review + Save**.\n6. Click **Save**.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_12"
      }
    }

    query "2.13" {
      description = "Azure CIS 2.13 Ensure 'Additional email addresses' is configured with a security contact email (Automated)"
      //email should be valid so if there is even not valid email it will pass
      expect_output = true
      query         = <<EOF
        SELECT subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Security Center emails the subscription owners whenever a high-severity alert is triggered for their subscription. You should provide a security contact email address as an additional email address.\n\nAzure Security Center emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the appropriate Management Group, Subscription, or Tenant.\n4. Click on `Email notifications`.\n5. Enter a valid security contact email address (or multiple addresses separated by commas) in the `Additional email addresses` field.\n6. Click **Save**.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_13"
        source          = "mage"
        summary         = "Security Center emails the subscription owners whenever a high-severity alert is triggered for their subscription. You should provide a security contact email address as an additional email address.\n\nAzure Security Center emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.\n"
      }
    }

    query "2.14" {
      description   = "Azure CIS 2.14 Ensure that 'Notify about alerts with the following severity' is set to 'High' (Automated)"
      expect_output = true
      query         = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alert_notifications = 'On';
    EOF
      risk {
        summary         = "Enables emailing security alerts to the subscription owner or other designated security contact. Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enables emailing security alerts to the subscription owner or other designated security contact. Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the appropriate Management Group, Subscription, or Tenant.\n4. Click on `Email notifications`.\n5. Enter a valid security contact email address in the `Additional email addresses` field.\n6. Under `Notification types`, check the check box next to `Notify about alerts with the following severity (or higher)`, and select `High` from the drop down menu.\n7. Click **Save**.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_14"
        source          = "mage"
      }
    }

    query "2.15" {
      description   = "Azure CIS 2.15 Ensure that 'All users with the following roles' is set to 'Owner' (Automated)"
      expect_output = true
      query         = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alerts_to_admins = 'On';
    EOF
      risk {
        description     = "Enable security alert emails to subscription owners. Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [Security Center](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0).\n2. Select `Pricing & settings` blade under Management.\n3. Click on the appropriate Management Group, Subscription, or Tenant.\n4. Click on `Email notifications`.\n5. Under `Email recipient`, select `Owner` in the drop down of the `All users with the following roles` field.\n7. Click **Save**.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_2_15"
        source          = "mage"
        summary         = "Enable security alert emails to subscription owners. Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }
  }

  policy "azure-cis-section-3" {
    description = "Azure CIS Section 3"

    query "3.1" {
      description = "Azure CIS 3.1: Ensure that 'Secure transfer required' is set to 'Enabled'"
      query       = <<EOF
        SELECT subscription_id, id, name, type
        FROM azure_storage_accounts
        WHERE NOT enable_https_traffic_only
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Enable data encryption in transit.\n\nThe secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each selected storage account, navigate to `settings` section\n3. Click on **Configuration**\n4. Navigate to `Security` section\n5. Set **Secure transfer required** to `Enabled`\n\n### From Command Line\n\nUse the below command to enable Secure transfer required for a Storage Account.\n\n```bash\naz storage account update --name <storageAccountName> --resource-group <resourceGroupName> --https-only true\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_1"
        source          = "mage"
        summary         = "Enable data encryption in transit.\n\nThe secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "3.2" {
      description = "Azure CIS 3.2: Ensure that storage account access keys are periodically regenerated"
      query       = <<EOF
        WITH regenerates_per_account AS (
          SELECT
            a.subscription_id,
            a.id,
            a.name,
            (
              SELECT COUNT(*)
              FROM azure_monitor_activity_logs logs
              WHERE logs.resource_id = a.id
                AND authorization_action IS NOT DISTINCT FROM 'Microsoft.Storage/storageAccounts/regenerateKey/action'
                AND status_value IS NOT DISTINCT FROM 'Succeeded'
            ) as count
          FROM azure_storage_accounts a
        )
        SELECT subscription_id, id, name
        FROM regenerates_per_account
        WHERE count = 0
      EOF
      risk {
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each selected storage account, go to `Activity` log from side bar\n3. Under **Timespan** drop-down, select Custom and choose Start time and End time such that it ranges 90 days\n4. Enter `RegenerateKey` in the **Search text box**\n5. Click **Apply**\n6. It should list out all RegenerateKey events. If no such event exists, then this is a finding.\n\nTo remediate, follow Microsoft Azure [documentation](https://docs.microsoft.com/en-us/azure/storage/common/storage-create-storage-account#regenerate-storage-access-keys) for regenerating storage account access keys.\n\n**Note:** By default, access keys are not regenerated periodically.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_2"
        source          = "mage"
        summary         = "Regenerate storage account access keys periodically.\n\nWhen a storage account is created, Azure generates two 512-bit storage access keys, which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result in these keys being compromised.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Regenerate storage account access keys periodically.\n\nWhen a storage account is created, Azure generates two 512-bit storage access keys, which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result in these keys being compromised.\n"
      }
    }

    query "3.3" {
      description = "Azure CIS 3.3: Ensure Storage logging is enabled for Queue service for read, write, and delete requests"
      query       = <<EOF
        SELECT subscription_id, id
        FROM azure_storage_accounts
        WHERE NOT ((queue_logging_settings -> 'Delete')::boolean
                   AND (queue_logging_settings -> 'Read')::boolean
                   AND (queue_logging_settings -> 'Write')::boolean)
      EOF
      risk {
        source          = "mage"
        summary         = "The Storage Queue service stores messages that may be read by any client who has access to the storage account. A queue can contain an unlimited number of messages, each of which can be up to 64KB in size using version 2011-08-18 or newer. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the queues. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis. Storage Analytics logging is not enabled by default for your storage account.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The Storage Queue service stores messages that may be read by any client who has access to the storage account. A queue can contain an unlimited number of messages, each of which can be up to 64KB in size using version 2011-08-18 or newer. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the queues. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis. Storage Analytics logging is not enabled by default for your storage account.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each selected storage account\n3. Navigate to `Monitoring (classic)` section from left bar. Click the **Diagnostics settings (classic)** blade\n4. Set the **Status** to `On`, if set to `Off`\n5. Select `Queue properties`\n6. Select `Read`, `Write` and `Delete` options under the **Logging** section to enable Storage `Logging` for Queue service.\n\n### From Command Line\n\nUse the below command to enable the Storage Logging for Queue service.\n\n```bash\naz storage logging update --account-name <storageAccountName> --account-key <storageAccountKey> --services q --log rwd --retention 90\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_3"
      }
    }

    query "3.4" {
      description   = "Azure CIS 3.4: Ensure that shared access signature tokens expire within an hour"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each selected storage account\n3. For each storage account, go to **Shared access signature**\n4. Set `Start and expiry date/time` within an hour\n\n**Note:** By default, expiration for `shared access signature` is set to 8 hour\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_4"
        source          = "mage"
        summary         = "Expire shared access signature tokens within an hour.\n\nA shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Expire shared access signature tokens within an hour.\n\nA shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour.\n"
      }
    }

    query "3.5" {
      description = "Azure CIS 3.5: Ensure that 'Public access level' is set to Private for blob containers"
      query       = <<EOF
        SELECT subscription_id, account_id, id, name
        FROM azure_storage_containers
        WHERE NOT deleted AND public_access != 'PublicAccessNone'
      EOF
      risk {
        description     = "Disable anonymous access to blob containers and disallow blob public access on storage account.\n\nAnonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token should be used for providing controlled and timed access to blob containers. If no\nanonymous access is needed on the storage account, it’s recommended to set allowBlobPublicAccess false.\n"
        recommendations = "### From Console\n\nFirst, follow Microsoft documentation and create [shared access signature tokens](https://docs.microsoft.com/en-us/rest/api/storageservices/delegating-access-with-a-shared-access-signature) for your blob containers. Then,\n\n1. Login to Azure Storage Accounts\n2. For each storage account, go to `Containers` under **DATA STORAGE**\n3. Select the container, click **Access policy**\n4. Set **Change access level** in top bar, to `Private (no anonymous access)`\n5. For each storage account overview page, under `Blob Service` check the value set\n6. Click on selected storage account `Configuration` under settings section of left bar\n7. Set **Disabled** if no anonymous access is needed on the storage account\n8. Click **Save**\n\n### From Command Line\n\n1. Identify the container name from the audit command\n\n2. Set the permission for public access to private(off) for the above container name, using the below command\n\n```bash\naz storage container set-permission --name <containerName> --public-access off --account-name <accountName> --account-key <accountKey>\n```\n\n3. Set Disabled if no anonymous access is wanted on the storage account\n\n```bash\naz storage account update --name <storage-account> --resource-group <resource-group> --allow-blob-public-access false\n```\n\n**Note:** By default, `Public access level` is set to `Private (no anonymous access)` for blob containers. By default, `AllowBlobPublicAccess` is set to `Null (allow in effect)` for storage account.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_5"
        source          = "mage"
        summary         = "Disable anonymous access to blob containers and disallow blob public access on storage account.\n\nAnonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token should be used for providing controlled and timed access to blob containers. If no\nanonymous access is needed on the storage account, it’s recommended to set allowBlobPublicAccess false.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "3.6" {
      description = "Azure CIS 3.6: Ensure default network access rule for Storage Accounts is set to deny"
      query       = <<EOF
        SELECT subscription_id, id, name
        FROM azure_storage_accounts
        WHERE network_rule_set_default_action != 'DefaultActionDeny'
      EOF
      risk {
        summary         = "Restricting default network access helps to provide a new layer of security, since storage accounts accept connections from clients on any network. To limit access to selected networks, the default action must be changed.\n\nStorage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges, to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Restricting default network access helps to provide a new layer of security, since storage accounts accept connections from clients on any network. To limit access to selected networks, the default action must be changed.\n\nStorage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges, to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each storage account, go to `Security + networking` section\n3. Click on the `Networking` settings\n4. Go to menu called `Firewalls and virtual networks`\n5. Ensure that you have elected to allow access from **Selected networks**\n6. Add rules to allow traffic from specific network.\n7. Click Save to apply your changes.\n\n### From Command Line\n\nUse the below command to update default-action to Deny.\n\n```bash\naz storage account update --name <StorageAccountName> --resource-group <resourceGroupName> --default-action Deny\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_6"
        source          = "mage"
      }
    }

    query "3.7" {
      description = "Azure CIS 3.7: Ensure 'Trusted Microsoft Services' is enabled for Storage Account access"
      query       = <<EOF
        SELECT subscription_id, id, name
        FROM azure_storage_accounts
        WHERE position('AzureServices' in network_rule_set_bypass) != 0
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules. These services will then use strong authentication to access the storage account. If the Allow trusted Microsoft services exception is enabled, the following services: Azure Backup, Azure Site Recovery, Azure DevTest Labs, Azure Event Grid, Azure Event Hubs, Azure Networking, Azure Monitor and Azure SQL Data Warehouse (when registered in the subscription), are granted access to the storage account.\n\nTurning on firewall rules for storage account will block access to incoming requests for data, including from other Azure services. This includes using the Portal, writing logs, etc. We can re-enable functionality. The customer can get access to services like Monitor, Networking, Hubs, and Event Grid by enabling \"Trusted Microsoft Services\" through exceptions. Also, Backup and Restore of Virtual Machines using unmanaged disks in storage accounts with network rules applied is supported via creating an exception.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each storage account, go to `Security + networking` section\n3. Click on the `Networking` settings\n4. Go to menu called `Firewalls and virtual networks`\n5. Ensure that you have elected to allow access from **Selected networks**\n6. In `Exceptions` section, enable check box for `Allow trusted Microsoft services to access this storage account`\n7. Click **Save** to apply your changes.\n\n### From Command Line\n\nUse the below command to update `trusted Microsoft services`.\n\n```bash\n az storage account update --name <StorageAccountName> --resource-group <resourceGroupName> --bypass AzureServices\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_7"
        source          = "mage"
        summary         = "Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules. These services will then use strong authentication to access the storage account. If the Allow trusted Microsoft services exception is enabled, the following services: Azure Backup, Azure Site Recovery, Azure DevTest Labs, Azure Event Grid, Azure Event Hubs, Azure Networking, Azure Monitor and Azure SQL Data Warehouse (when registered in the subscription), are granted access to the storage account.\n\nTurning on firewall rules for storage account will block access to incoming requests for data, including from other Azure services. This includes using the Portal, writing logs, etc. We can re-enable functionality. The customer can get access to services like Monitor, Networking, Hubs, and Event Grid by enabling \"Trusted Microsoft Services\" through exceptions. Also, Backup and Restore of Virtual Machines using unmanaged disks in storage accounts with network rules applied is supported via creating an exception.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "3.8" {
      description = "Azure CIS 3.8: Ensure soft delete is enabled for Azure Storage"
      query       = <<EOF
        SELECT
        FROM azure_storage_accounts a LEFT OUTER JOIN azure_storage_blob_services b ON a.cq_id=b.account_cq_id
        WHERE delete_retention_policy_enabled IS NULL OR NOT delete_retention_policy_enabled
      EOF
      risk {
        summary         = "The Azure Storage blobs contain data like ePHI, Financial, secret or personal. Erroneously modified or deleted accidentally by an application or other storage account user cause data loss or data unavailability. It is recommended the Azure Storage be made recoverable by enabling soft delete configuration. This is to save and recover data when blobs or blob snapshots are deleted.\n\nThere could be scenarios where users accidentally run delete commands on Azure Storage blobs or blob snapshot or attacker/malicious user does it deliberately to cause disruption. Deleting an Azure Storage blob leads to immediate data loss / non-accessible data. There is a property of Azure Storage blob service to make recoverable blobs.\n\n  - Soft Delete\n\n    Enabling this configuration for azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects remain recoverable for a particular time which set in the \"*Retention policies*\" `[Retention policies can be 7 days to 365 days]`.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The Azure Storage blobs contain data like ePHI, Financial, secret or personal. Erroneously modified or deleted accidentally by an application or other storage account user cause data loss or data unavailability. It is recommended the Azure Storage be made recoverable by enabling soft delete configuration. This is to save and recover data when blobs or blob snapshots are deleted.\n\nThere could be scenarios where users accidentally run delete commands on Azure Storage blobs or blob snapshot or attacker/malicious user does it deliberately to cause disruption. Deleting an Azure Storage blob leads to immediate data loss / non-accessible data. There is a property of Azure Storage blob service to make recoverable blobs.\n\n  - Soft Delete\n\n    Enabling this configuration for azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects remain recoverable for a particular time which set in the \"*Retention policies*\" `[Retention policies can be 7 days to 365 days]`.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each Storage Account, navigate to `Data Protection` under `Data management` section\n3. Select `set soft delete enabled` and enter a number of days you want to retain soft deleted data.\n\n### From Command Line\n\nUpdate `retention days` in below command\n\n```bash\naz storage blob service-properties delete-policy update --days-retained <RetentionDaysValue> --account-name <StorageAccountName> --enable true\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_8"
        source          = "mage"
      }
    }

    query "3.9" {
      description = "Azure CIS 3.9: Ensure storage for critical data are encrypted with Customer Managed Key"
      query       = <<EOF
        SELECT subscription_id, id
        FROM azure_storage_accounts
        WHERE encryption_key_source = 'Microsoft.Storage'
      EOF
      risk {
        description     = "Enable sensitive data encryption at rest using Customer Managed Keys rather than Microsoft Managed keys.\n\nBy default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. For each storage account, go to **Encryption** under `Security + networking`\n3. Set **Customer Managed Keys**\n4. Select the Encryption key and enter the appropriate setting value as documented [here](https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption)\n5. Click **Save**\n\n**Note:** By default, Encryption type is set to Microsoft Managed Keys.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_9"
        source          = "mage"
        summary         = "Enable sensitive data encryption at rest using Customer Managed Keys rather than Microsoft Managed keys.\n\nBy default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "3.10" {
      description = "Azure CIS 3.10: Ensure Storage logging is enabled for Blob service for read, write, and delete requests"
      query       = <<EOF
        SELECT subscription_id, id
        FROM azure_storage_accounts
        WHERE NOT ((blob_logging_settings -> 'Delete')::boolean
                   AND (blob_logging_settings -> 'Read')::boolean
                   AND (blob_logging_settings -> 'Write')::boolean)
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "The Storage Blob service provides scalable, cost-efficient objective storage in the cloud. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the blobs. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. Select the specific Storage Account.\n3. Navigate to `Monitoring (classic)` section from left bar. Click the **Diagnostics settings (classic)** blade\n4. Set the `Status` to **On**, if set to Off\n5. Select `Blob properties`\n6. Select `Read`, `Write` and `Delete` options under the **Logging** section to enable Storage `Logging` for Blob service.\n\n### From Command Line\n\nUse the below command to enable the Storage Logging for Blob service.\n\n```bash\naz storage logging update --account-name <storageAccountName> --account-key <storageAccountKey> --services b --log rwd --retention 90\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_10"
        source          = "mage"
        summary         = "The Storage Blob service provides scalable, cost-efficient objective storage in the cloud. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the blobs. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "3.11" {
      description   = "Azure CIS 3.11: Ensure Storage logging is enabled for Table service for read, write, and delete requests"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The Storage Table storage is a service that stores structure NoSQL data in the cloud, providing a key/attribute store with a schema less design. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the tables. Storage Logging log entries contain the following information about individual requests. Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.\n"
        recommendations = "### From Console\n\n1. Login to Azure Storage Accounts\n2. Select the specific Storage Account.\n3. Navigate to `Monitoring (classic)` section from left bar. Click the **Diagnostics settings (classic)** blade\n4. Set the `Status` to **On**, if set to Off\n5. Select `Table properties`\n6. Select `Read`, `Write` and `Delete` options under the **Logging** section to enable Storage `Logging` for Table service.\n\n### From Command Line\n\nUse the below command to enable the Storage Logging for Table service.\n\n```bash\naz storage logging update --account-name <storageAccountName> --account-key <storageAccountKey> --services t --log rwd --retention 90\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_3_11"
        source          = "mage"
        summary         = "The Storage Table storage is a service that stores structure NoSQL data in the cloud, providing a key/attribute store with a schema less design. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the tables. Storage Logging log entries contain the following information about individual requests. Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.\n\nStorage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.\n"
      }
    }
  }

  policy "azure-cis-section-4" {
    description = "Azure CIS Section 4"

    query "4.1.1" {
      description = "Azure CIS 4.1.1 Ensure that 'Auditing' is set to 'On' (Automated)"
      query       = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.state AS auditing_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
        s.cq_id = assdbap.server_cq_id
        WHERE assdbap.state != 'Enabled';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable auditing on SQL Servers. Enabling *auditing* at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.\n\nAuditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.\n\nDefault setting for *Auditing* is set to *Off*.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Auditing`.\n4. Set `Enable Azure SQL Auditing` to **On** and select a storage account for log destination.\n5. Click **Save**.\n\n### From PowerShell\n\n1. Get the list of all SQL Servers\n\n```powershell\nGet-AzureRmSqlServer\n```\n\n2. For each Server, enable auditing.\n\n```powershell\nSet-AzureRmSqlServerAuditingPolicy -ResourceGroupName <resource group name> - ServerName <server name> -AuditType <audit type> -StorageAccountName <storage account name>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_1_1"
        source          = "mage"
        summary         = "It is recommended to enable auditing on SQL Servers. Enabling *auditing* at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.\n\nAuditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.\n\nDefault setting for *Auditing* is set to *Off*.\n"
      }
    }

    query "4.1.2" {
      description = "Azure CIS 4.1.2 Ensure that 'Data encryption' is set to 'On' on a SQL Database (Automated)"
      query       = <<EOF
        SELECT s.subscription_id , asd.id AS database_id, asd.transparent_data_encryption -> 'properties' ->> 'status' AS encryption_status
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases asd ON
        s.cq_id = asd.server_cq_id
        WHERE asd.transparent_data_encryption -> 'properties' ->> 'status' != 'Enabled';
    EOF
      risk {
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Databases](https://portal.azure.com/#create/Microsoft.SQLDatabase).\n2. For each DB instance, go to Security section from left pane.\n3. Click on `Transparent data encryption`.\n4. Set `Transparent data encryption` to **On**.\n5. Click **Save**.\n\n### From Command Line\n\n```bash\naz sql db tde set --resource-group <resourceGroup> --server <dbServerName> -- database <dbName> --status Enabled\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_1_2"
        source          = "mage"
        summary         = "It is recommended to enable *Transparent Data Encryption* on every SQL database. Azure SQL database *transparent data encryption* helps to protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups and transaction log files at rest without requiring changes to the application.\n\nTransparent Data Encryption (TDE) can be enabled or disabled on individual SQL Database level and not on the SQL Server level. TDE cannot be used to encrypt the logical master database in SQL Database.\n\nDefault setting for *Transparent data encryption* is set to *On*.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *Transparent Data Encryption* on every SQL database. Azure SQL database *transparent data encryption* helps to protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups and transaction log files at rest without requiring changes to the application.\n\nTransparent Data Encryption (TDE) can be enabled or disabled on individual SQL Database level and not on the SQL Server level. TDE cannot be used to encrypt the logical master database in SQL Database.\n\nDefault setting for *Transparent data encryption* is set to *On*.\n"
      }
    }

    query "4.1.3" {
      description = "Azure CIS 4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)"
      query       = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.retention_days AS auditing_retention_days
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
                s.cq_id = assdbap.server_cq_id
        WHERE assdbap.retention_days < 90;
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "It is recommended SQL Server *Audit Retention* should be configured to be greater than 90 days. Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.\n\nDefault setting for SQL Server audit storage is *disabled*.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Auditing`.\n4. Set `Enable Azure SQL Auditing` to **On** and select a storage account for log destination.\n5. Set `Retention Days` setting to greater than **90** days.\n6. Click **Save**.\n\n### From PowerShell\n\n```powershell\nset-AzureRmSqlServerAuditing -ResourceGroupName <resource group name> - ServerName <server name> -RetentionInDays <Number of Days to retain the audit logs, should be 90days minimum>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_1_3"
        source          = "mage"
        summary         = "It is recommended SQL Server *Audit Retention* should be configured to be greater than 90 days. Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.\n\nDefault setting for SQL Server audit storage is *disabled*.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "4.2.1" {
      description = "Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled' (Automated)"
      query       = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, d."name" AS database_name, p.state AS policy_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases d ON
        s.cq_id = d.server_cq_id
        LEFT JOIN azure_sql_database_db_threat_detection_policies p ON
        d.cq_id = p.database_cq_id
        WHERE p.state != 'Enabled';
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *Azure Defender for SQL* on critical SQL Servers. Azure Defender for SQL is a unified package for advanced security capabilities.\n\nIt is available for *Azure SQL Database*, *Azure SQL Managed Instance*, and *Azure Synapse Analytics*. It includes functionality for discovering and classifying sensitive data, surfacing and mitigating potential database vulnerabilities, and detecting anomalous activities that could indicate a threat to your database. It provides a single go-to location for enabling and managing these capabilities.\n\nDefault setting for Azure Defender for SQL is *Off*.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Security Center`.\n4. Click `Enable Azure Defender for SQL`.\n\n### From PowerShell\n\n```powershell\nSet-AzSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name> -ServerName <server name> -EmailAdmins $True\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_2_1"
        source          = "mage"
        summary         = "It is recommended to enable *Azure Defender for SQL* on critical SQL Servers. Azure Defender for SQL is a unified package for advanced security capabilities.\n\nIt is available for *Azure SQL Database*, *Azure SQL Managed Instance*, and *Azure Synapse Analytics*. It includes functionality for discovering and classifying sensitive data, surfacing and mitigating potential database vulnerabilities, and detecting anomalous activities that could indicate a threat to your database. It provides a single go-to location for enabling and managing these capabilities.\n\nDefault setting for Azure Defender for SQL is *Off*.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "4.2.2" {
      description = "Azure CIS 4.2.2 Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account (Automated)"
      // experimentally checked and storage_container_path becomes NULL when storage account is disabled in assessment policy
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.storage_container_path IS NULL OR a.storage_container_path = ''
    EOF
      risk {
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_2_2"
        source          = "mage"
        summary         = "It is recommended to enable Vulnerability Assessment (VA) service scans for critical SQL servers and corresponding SQL databases. Enabling Azure Defender for SQL server does not enables Vulnerability Assessment capability for individual SQL databases unless storage account is set to store the scanning data and reports.\n\nThe Vulnerability Assessment service scans databases for known security vulnerabilities and highlight deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data. Results of the scan include actionable steps to resolve each issue and provide customized remediation scripts where applicable.\n\nEnabling Azure Defender for SQL does not enable VA scanning by setting Storage Account automatically.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable Vulnerability Assessment (VA) service scans for critical SQL servers and corresponding SQL databases. Enabling Azure Defender for SQL server does not enables Vulnerability Assessment capability for individual SQL databases unless storage account is set to store the scanning data and reports.\n\nThe Vulnerability Assessment service scans databases for known security vulnerabilities and highlight deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data. Results of the scan include actionable steps to resolve each issue and provide customized remediation scripts where applicable.\n\nEnabling Azure Defender for SQL does not enable VA scanning by setting Storage Account automatically.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Security Center`.\n4. Make sure `Enable Azure Defender for SQL` is `On`.\n5. Select `Configure` next to Azure Defender for SQL: Enabled at the server-level.\n6. In section `VULNERABILITY ASSESSMENT SETTINGS`, select subscription and storage account.\n7. Click **Save**.\n\n### From PowerShell\n\nEnable Azure Defender for a SQL if not enabled\n\n```powershell\nSet-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name> -ServerName <server name> -EmailAdmins $True\n```\n\nTo enable ADS-VA service by setting Storage Account\n\n```powershell\nUpdate-AzSqlServerVulnerabilityAssessmentSetting ` -ResourceGroupName \"<resource group name>\"`\n-ServerName \"<Server Name>\"`\n-StorageAccountName \"<Storage Name from same subscription and same Location\" `\n-ScanResultsContainerName \"vulnerability-assessment\" ` -RecurringScansInterval Weekly `\n-EmailSubscriptionAdmins $true `\n-NotificationEmail @(\"mail1@mail.com\" , \"mail2@mail.com\")\n```\n"
      }
    }


    query "4.2.3" {
      description = "Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server (Automated)"
      query       = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_is_enabled IS NULL
        OR a.recurring_scans_is_enabled != TRUE;
    EOF
      risk {
        summary         = "It is recommended to enable Vulnerability Assessment (VA) *Periodic recurring scans* for critical SQL servers and corresponding SQL databases.\n\nVA setting *Periodic recurring scans* schedules periodic (weekly) vulnerability scanning. Periodic and regular vulnerability scanning provides risk visibility based on updated known vulnerability signatures and best practices.\n\nEnabling Azure Defender for SQL enables *Periodic recurring scans* by default but does not configure the Storage account.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable Vulnerability Assessment (VA) *Periodic recurring scans* for critical SQL servers and corresponding SQL databases.\n\nVA setting *Periodic recurring scans* schedules periodic (weekly) vulnerability scanning. Periodic and regular vulnerability scanning provides risk visibility based on updated known vulnerability signatures and best practices.\n\nEnabling Azure Defender for SQL enables *Periodic recurring scans* by default but does not configure the Storage account.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Security Center`.\n4. Make sure `Enable Azure Defender for SQL` is `On`.\n5. Select `Configure` next to Azure Defender for SQL: Enabled at the server-level.\n6. In section `VULNERABILITY ASSESSMENT SETTINGS`, select subscription and storage account.\n7. Set `Periodic recurring scans` to **ON**.\n8. Click **Save**.\n\n### From PowerShell\n\nEnable Azure Defender for a SQL if not enabled\n\n```powershell\nSet-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name> -ServerName <server name> -EmailAdmins $True\n```\n\nEnable ADS-VA service with `Periodic recurring scans`\n\n```powershell\nUpdate-AzSqlServerVulnerabilityAssessmentSetting ` -ResourceGroupName \"<resource group name>\"`\n-ServerName \"<Server Name>\"`\n-StorageAccountName \"<Storage Name from same subscription and same Location\" `\n-ScanResultsContainerName \"vulnerability-assessment\" ` -RecurringScansInterval Weekly `\n-EmailSubscriptionAdmins $true `\n-NotificationEmail @(\"mail1@mail.com\" , \"mail2@mail.com\")\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_2_3"
        source          = "mage"
      }
    }

    query "4.2.4" {
      description = "Azure CIS 4.2.4 Ensure that VA setting Send scan reports to is configured for a SQL server (Automated)"
      query       = <<EOF
        WITH vulnerability_emails AS (SELECT id, UNNEST(recurring_scans_emails) AS emails
        FROM azure_sql_server_vulnerability_assessments v), emails_count AS (SELECT id, count(emails) AS emails_number
        FROM vulnerability_emails
        GROUP BY id) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, sv."name" AS assesment_name, c.emails_number AS emails
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments sv ON
        s.cq_id = sv.server_cq_id
        LEFT JOIN emails_count c ON
        sv.id = c.id
        WHERE c.emails_number = 0
        OR c.emails_number IS NULL;
    EOF
      risk {
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Security Center`.\n4. Make sure `Enable Azure Defender for SQL` is `On`.\n5. Select `Configure` next to Azure Defender for SQL: Enabled at the server-level.\n6. In section `VULNERABILITY ASSESSMENT SETTINGS`, select subscription and storage account.\n7. Set `Periodic recurring scans` to **ON**.\n8. Configure email ids for concerned stakeholders at `Send scan reports to`.\n9. Click **Save**.\n\n### From PowerShell\n\nEnable Azure Defender for a SQL if not enabled\n\n```powershell\nSet-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name> -ServerName <server name> -EmailAdmins $True\n```\n\nEnable ADS-VA service and set `Send scan reports to`\n\n```powershell\nUpdate-AzSqlServerVulnerabilityAssessmentSetting ` -ResourceGroupName \"<resource group name>\"`\n-ServerName \"<Server Name>\"`\n-StorageAccountName \"<Storage Name from same subscription and same Location\" `\n-ScanResultsContainerName \"vulnerability-assessment\" `\n-RecurringScansInterval Weekly `\n-EmailSubscriptionAdmins $true `\n-NotificationEmail @(\"mail1@mail.com\" , \"mail2@mail.com\")\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_2_4"
        source          = "mage"
        summary         = "It is recommended to configure *Send scan reports to* with email ids of concerned data owners or stakeholders for a critical SQL servers.\n\nVulnerability Assessment (VA) scan reports and alerts will be sent to email ids configured at *Send scan reports to*. This may help in reducing time required for identifying risks and taking corrective measures.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to configure *Send scan reports to* with email ids of concerned data owners or stakeholders for a critical SQL servers.\n\nVulnerability Assessment (VA) scan reports and alerts will be sent to email ids configured at *Send scan reports to*. This may help in reducing time required for identifying risks and taking corrective measures.\n"
      }
    }

    query "4.2.5" {
      description = "Azure CIS 4.2.5 Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server (Automated)"
      query       = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_email_subscription_admins IS NULL
        OR a.recurring_scans_email_subscription_admins != TRUE;
    EOF
      risk {
        description     = "It is recommended to enable Vulnerability Assessment (VA) setting *Also send email notifications to admins and subscription owners*.\n\nVA scan reports and alerts will be sent to admins and subscription owners by enabling setting *Also send email notifications to admins and subscription owners*. This may help in reducing time required for identifying risks and taking corrective measures.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For each server instance, go to Security section from left pane.\n3. Click on `Security Center`.\n4. Make sure `Enable Azure Defender for SQL` is `On`.\n5. Select `Configure` next to Azure Defender for SQL: Enabled at the server-level.\n6. In section `VULNERABILITY ASSESSMENT SETTINGS`, select subscription and storage account.\n7. Set `Periodic recurring scans` to **ON**.\n8. Configure email ids for concerned stakeholders at `Send scan reports to`.\n9. Check `Also send email notifications to admins and subscription owners`.\n10. Click **Save**.\n\n### From PowerShell\n\nEnable Azure Defender for a SQL if not enabled\n\n```powershell\nSet-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name> -ServerName <server name> -EmailAdmins $True\n```\n\nEnable ADS-VA service and set `Send scan reports to`\n\n```powershell\nUpdate-AzSqlServerVulnerabilityAssessmentSetting ` -ResourceGroupName \"<resource group name>\"`\n-ServerName \"<Server Name>\"`\n-StorageAccountName \"<Storage Name from same subscription and same Location\" `\n-ScanResultsContainerName \"vulnerability-assessment\" `\n-RecurringScansInterval Weekly `\n-EmailSubscriptionAdmins $true `\n-NotificationEmail @(\"mail1@mail.com\" , \"mail2@mail.com\")\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_2_5"
        source          = "mage"
        summary         = "It is recommended to enable Vulnerability Assessment (VA) setting *Also send email notifications to admins and subscription owners*.\n\nVA scan reports and alerts will be sent to admins and subscription owners by enabling setting *Also send email notifications to admins and subscription owners*. This may help in reducing time required for identifying risks and taking corrective measures.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "4.3.1" {
      description = "Azure CIS 4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        SELECT subscription_id, id AS server_id, "name", ssl_enforcement AS server_name
        FROM azure_postgresql_servers aps
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
      risk {
        source          = "mage"
        summary         = "It is recommended to enable SSL connection on PostgreSQL Servers. *SSL connectivity* helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against attacks by encrypting the data stream between the server and application.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable SSL connection on PostgreSQL Servers. *SSL connectivity* helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against attacks by encrypting the data stream between the server and application.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Connection security` and go to `SSL settings`.\n4. For `Enforce SSL connection`, click on **ENABLED**.\n\n### From Command Line\n\nEnable `enforce ssl connection` for PostgreSQL Database\n\n```bash\naz postgres server update --resource-group <resourceGroupName> --name <serverName> --ssl-enforcement Enabled\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_1"
      }
    }

    query "4.3.2" {
      description = "Azure CIS 4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server (Automated)"
      query       = <<EOF
        SELECT subscription_id, id AS server_id, "name" AS server_name, ssl_enforcement
        FROM azure_mysql_servers ams
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *SSL connection* on MYSQL Servers. SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against attacks by encrypting the data stream between the server and application.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.MySQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Connection security` and go to `SSL settings`.\n4. For `Enforce SSL connection`, click on **ENABLED**.\n\n### From Command Line\n\nEnable `enforce ssl connection` for PostgreSQL Database\n\n```bash\naz mysql server show --resource-group myresourcegroup --name <resourceGroupName> --query sslEnforcement\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_2"
        source          = "mage"
        summary         = "It is recommended to enable *SSL connection* on MYSQL Servers. SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against attacks by encrypting the data stream between the server and application.\n"
        attack_surface  = "CLOUD"
      }
    }


    query "4.3.3" {
      description = "Azure CIS 4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_checkpoints') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_checkpoints' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *log_checkpoints* on PostgreSQL Servers. Enabling *log_checkpoints* helps the PostgreSQL database to Log each checkpoint in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Server parameters`.\n4. Search for `log_checkpoints`.\n5. Click **ON** and save.\n\n### From Command Line\n\nCommand to update `log_checkpoints` configuration\n\n```bash\naz postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_checkpoints --value on\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_3"
        source          = "mage"
        summary         = "It is recommended to enable *log_checkpoints* on PostgreSQL Servers. Enabling *log_checkpoints* helps the PostgreSQL database to Log each checkpoint in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "4.3.4" {
      description = "Azure CIS 4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_connections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_connections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *log_connections* on PostgreSQL Servers. Enabling *log_connections* helps PostgreSQL database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Server parameters`.\n4. Search for `log_connections`.\n5. Click **ON** and save.\n\n### From Command Line\n\nCommand to update `log_connections` configuration\n\n```bash\naz postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_connections --value on\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_4"
        source          = "mage"
        summary         = "It is recommended to enable *log_connections* on PostgreSQL Servers. Enabling *log_connections* helps PostgreSQL database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.\n"
      }
    }

    query "4.3.5" {
      description = "Azure CIS 4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_disconnections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_disconnections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *log_disconnections* on PostgreSQL Servers. Enabling *log_disconnections* helps PostgreSQL database to logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Server parameters`.\n4. Search for `log_disconnections`.\n5. Click **ON** and save.\n\n### From Command Line\n\nCommand to update `log_disconnections` configuration\n\n```bash\naz postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections --value on\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_5"
        source          = "mage"
        summary         = "It is recommended to enable *log_disconnections* on PostgreSQL Servers. Enabling *log_disconnections* helps PostgreSQL database to logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
      }
    }

    query "4.3.6" {
      description = "Azure CIS 4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'connection_throttling') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'connection_throttling' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *connection_throttling* on PostgreSQL Servers. Enabling *connection_throttling* helps the PostgreSQL database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful denial of service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Server parameters`.\n4. Search for `connection_throttling`.\n5. Click **ON** and save.\n\n### From Command Line\n\nCommand to update `connection_throttling` configuration\n\n```bash\naz postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name connection_throttling --value on\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_6"
        source          = "mage"
        summary         = "It is recommended to enable *connection_throttling* on PostgreSQL Servers. Enabling *connection_throttling* helps the PostgreSQL database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful denial of service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
      }
    }

    query "4.3.7" {
      description = "Azure CIS 4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (Automated)"
      query       = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                        aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_retention_days') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_retention_days' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
                s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value::INTEGER < 3;
    EOF
      risk {
        summary         = "It is recommended to enable *log_retention_days* on PostgreSQL Servers. Enabling *log_retention_days* helps PostgreSQL database to sets number of days a log file is retained which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable *log_retention_days* on PostgreSQL Servers. Enabling *log_retention_days* helps PostgreSQL database to sets number of days a log file is retained which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\n"
        recommendations = "### From Console\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Server parameters`.\n4. Search for `log_retention_days`.\n5. Enter value in range of `4-7` and click save.\n\n### From Command Line\n\nCommand to update `log_retention_days` configuration\n\n```bash\naz postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_retention_days\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_7"
        source          = "mage"
      }
    }

    query "4.3.8" {
      description = "Azure CIS 4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled (Manual)"
      query       = <<EOF
        SELECT aps.subscription_id, aps.id AS server_id, aps."name" AS server_name, apsfr."name" AS rule_name, apsfr.start_ip_address, apsfr.end_ip_address
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_firewall_rules apsfr ON
        aps.cq_id = apsfr.server_cq_id
        WHERE apsfr."name" = 'AllowAllAzureIps'
        OR (apsfr.start_ip_address = '0.0.0.0'
        AND apsfr.end_ip_address = '0.0.0.0')
    EOF
      risk {
        summary         = "It is recommended to disable access from Azure services to PostgreSQL Database Server. When access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, setup firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to disable access from Azure services to PostgreSQL Database Server. When access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, setup firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks.\n"
        recommendations = "### From Console\n\nPerform the following action to check whether access from Azure services is enabled:\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Connection security`.\n4. In Firewall rules, ensure `Allow access to Azure services` is set to **No**.\n\nPerform the following action to disable access from Azure services:\n\n1. Login to Azure console and navigate to [PostgreSQL Servers](https://portal.azure.com/#create/Microsoft.PostgreSQLServer).\n2. For each database, go to `Settings` section from left pane.\n3. Click on `Connection security`.\n4. In Firewall rules, click **No** for `Allow access to Azure services`.\n\n### From Command Line\n\nCommand to delete the AllowAllAzureIps rule for PostgreSQL Database\n\n```bash\naz postgres server firewall-rule delete --name AllowAllAzureIps --resource- group <resourceGroupName> --server-name <serverName>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_3_8"
        source          = "mage"
      }
    }

    query "4.4" {
      description = "Azure CIS 4.4 Ensure that Azure Active Directory Admin is configured (Automated)"
      query       = <<EOF
        WITH ad_admins_count AS( SELECT ass.cq_id, count(*) AS admins_count
        FROM azure_sql_servers ass
        LEFT JOIN azure_sql_server_admins assa  ON
        ass.cq_id = assa.server_cq_id WHERE assa.administrator_type = 'ActiveDirectory' GROUP BY ass.cq_id,
        assa.administrator_type ) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, a.admins_count AS "ad_admins_count"
        FROM azure_sql_servers s
        LEFT JOIN ad_admins_count a ON
                s.cq_id = a.cq_id
        WHERE a.admins_count IS NULL
        OR a.admins_count = 0;
    EOF
      risk {
        description     = "It is recommended to use *Azure Active Directory Authentication* for authentication with SQL Database. It is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management.\n\n  - It provides an alternative to SQL Server authentication.\n  - Helps stop the proliferation of user identities across database servers and manage password rotation in a one place.\n  - Customers can manage database permissions using external (AAD) groups.\n  - Azure AD authentication uses contained database users to authenticate identities at the database level.\n  - Azure AD supports token-based authentication for applications connecting to SQL database.\n  - Azure AD authentication supports ADFS (domain federation) or native user/password authentication for a local Azure Active Directory without domain      synchronization.\n  - Azure AD supports connections from SQL Server Management Studio that use Active Directory Universal Authentication, which includes Multi-Factor Authentication (MFA). MFA includes strong authentication with a range of easy verification options — phone call, text message, smart cards with pin, or mobile app notification.\n"
        recommendations = "### From Console\n\nPerform the following action to check whether access from Azure services is enabled:\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For SQL server, go to `Settings` section from left pane.\n3. Click on `Active Directory admin`.\n4. Click on `Set admin` and select an admin.\n5. Click **Save**.\n\n### From Command Line\n\nGet ObjectID of user\n\n```bash\naz ad user list --query \"[?mail==<emailId of user>].{mail:mail, userPrincipalName:userPrincipalName, objectId:objectId}\"\n```\n\nFor each Server, set AD Admin\n\n```bash\naz sql server ad-admin create --resource-group <resource group name> --server <server name> --display-name <display name> --object-id <object id of user>\n```\n\n**Note** By default Azure Active Directory Authentication for SQL Database/Server is not enabled.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_4"
        source          = "mage"
        summary         = "It is recommended to use *Azure Active Directory Authentication* for authentication with SQL Database. It is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management.\n\n  - It provides an alternative to SQL Server authentication.\n  - Helps stop the proliferation of user identities across database servers and manage password rotation in a one place.\n  - Customers can manage database permissions using external (AAD) groups.\n  - Azure AD authentication uses contained database users to authenticate identities at the database level.\n  - Azure AD supports token-based authentication for applications connecting to SQL database.\n  - Azure AD authentication supports ADFS (domain federation) or native user/password authentication for a local Azure Active Directory without domain      synchronization.\n  - Azure AD supports connections from SQL Server Management Studio that use Active Directory Universal Authentication, which includes Multi-Factor Authentication (MFA). MFA includes strong authentication with a range of easy verification options — phone call, text message, smart cards with pin, or mobile app notification.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "4.5" {
      description = "Azure CIS 4.5 Ensure SQL server's TDE protector is encrypted with Customer-managed key (Automated)"
      query       = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, p.kind AS protector_kind
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_encryption_protectors p ON
        s.cq_id = p.server_cq_id
        WHERE p.kind != 'azurekeyvault'
        OR p.server_key_type != 'AzureKeyVault'
        OR uri IS NULL;
    EOF
      risk {
        summary         = "TDE with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service.\n\nWith TDE, data is encrypted at rest with a symmetric key (called the database encryption key) stored in the database or data warehouse distribution. To protect this data encryption key (DEK) in the past, only a certificate that the Azure SQL Service managed could be used. Now, with Customer-managed key support for TDE, the DEK can be protected with an asymmetric key that is stored in the Key Vault. Key Vault is a highly available and scalable cloud-based key store which offers central key management.\n\nBased on business needs or criticality of data/databases hosted a SQL server, it is recommended that the TDE protector is encrypted by a key that is managed by the data owner (Customer-managed key).\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "TDE with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service.\n\nWith TDE, data is encrypted at rest with a symmetric key (called the database encryption key) stored in the database or data warehouse distribution. To protect this data encryption key (DEK) in the past, only a certificate that the Azure SQL Service managed could be used. Now, with Customer-managed key support for TDE, the DEK can be protected with an asymmetric key that is stored in the Key Vault. Key Vault is a highly available and scalable cloud-based key store which offers central key management.\n\nBased on business needs or criticality of data/databases hosted a SQL server, it is recommended that the TDE protector is encrypted by a key that is managed by the data owner (Customer-managed key).\n"
        recommendations = "### From Console\n\nPerform the following action to check whether access from Azure services is enabled:\n\n1. Login to Azure console and navigate to [SQL Servers](https://portal.azure.com/#create/Microsoft.SQLServer).\n2. For required SQL server instance, go to `Security` section from left pane.\n3. Click on `Transparent data encryption`.\n4. Select `Customer-managed key` and select an admin.\n5. Browse through your key vaults to select an existing key or create a new key in Key Vault.\n6. Check `Make selected key the default TDE protector`.\n5. Click **Save**.\n\n### From Command Line\n\nCommand to encrypt SQL server's TDE protector with a Customer-managed key\n\n```bash\naz sql server tde-key >> Set --resource-group <resourceName> --server <dbServerName> --server-key-type {AzureKeyVault} [--kid <keyIdentifier>]\n```\n\n**Note**\n- By Default, Microsoft managed TDE protector is enabled for a SQL server and is encrypted by Service-managed key.\n- Ensuring TDE is protected by a Customer-managed key on SQL Server does not ensures the encryption of SQL Databases. TDE setting on individual SQL database decides whether database is encrypted or not\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_4_5"
        source          = "mage"
      }
    }
  }

  policy "azure-cis-section-5" {
    description = "Azure CIS Section 5"

    query "5.1.1" {
      description   = "Azure CIS 5.1.1: Ensure that a 'Diagnostics Setting' exists"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        recommendations = "### From Console\n\n1. Click on the resource that has a diagnostic status of disabled\n2. Select Add **Diagnostic Settings**\n3. Enter a Diagnostic setting name\n4. Select the appropriate log, metric, and destination. (This may be Log Analytics/Storage account or Event Hub)\n5. Click **save**\n\n**Note:** By default, diagnostic setting is not set.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_1_1"
        source          = "mage"
        summary         = "Enable Diagnostic settings for exporting activity logs. Diagnostic setting are available for each individual resources within a subscription. Settings should be configured for all appropriate resources for your environment.\n\nA diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enable Diagnostic settings for exporting activity logs. Diagnostic setting are available for each individual resources within a subscription. Settings should be configured for all appropriate resources for your environment.\n\nA diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.\n"
      }
    }

    query "5.1.2" {
      description = "Azure CIS 5.1.2: Ensure Diagnostic Setting captures appropriate categories"
      query       = <<EOF
        WITH subscription_categories AS (
          SELECT DISTINCT
            subs.id,
            subs.subscription_id,
            CASE
              WHEN ds.cq_id = logs.diagnostic_setting_cq_id THEN logs.category
              ELSE NULL
            END AS category
          FROM
            azure_subscription_subscriptions subs
              LEFT OUTER JOIN azure_monitor_diagnostic_settings ds
              ON subs.id=ds.resource_uri,
            azure_monitor_diagnostic_setting_logs logs
        )
        SELECT id, subscription_id
        FROM subscription_categories
        WHERE
          category IS NULL
          OR category IN ('Administrative', 'Alert', 'Policy', 'Security')
        GROUP by id, subscription_id
        HAVING COUNT(category) < 4
      EOF
      risk {
        summary         = "The diagnostic setting should be configured to log the appropriate activities from the control/management plane.\n\nA diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The diagnostic setting should be configured to log the appropriate activities from the control/management plane.\n\nA diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor console`\n2. Click **Activity log**\n3. Click on **Diagnostic settings**\n4. Click on `Add` or `Edit` Settings for the diagnostic settings entry\n5. Ensure that the following categories are checked: `Administrative`, `Alert`, `Policy`, and `Security`\n\n**Note:** By default, diagnostic setting is not set.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_1_2"
        source          = "mage"
      }
    }

    query "5.1.3" {
      description = "Ensure the storage container storing the activity logs is not publicly accessible"
      query       = <<EOF
        SELECT a.subscription_id AS subscription_id, a.id AS account_id, c.id AS container_id, c.name AS container_name
        FROM azure_storage_accounts a JOIN azure_storage_containers c ON a.cq_id=c.account_cq_id
        WHERE a.id IN (SELECT DISTINCT storage_account_id FROM azure_monitor_log_profiles)
              AND c.name LIKE 'insights-%'
              AND c.public_access != 'None'
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "The storage account container containing the activity log export should not be publicly accessible.\n\nAllowing public access to activity log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.\n"
        recommendations = "### From Console\n\n1. Search for Storage Accounts to access Storage account blade\n2. Click on the `storage account name`\n3. In Section Blob Service click **Containers** in side bar under `Data storage`. It will list all the containers in next blade\n4. Look for a record with container named as `insight-operational-logs` used for the logging activities.\n5. Click Access Policy from Context Menu and set Public Access Level to Private (no anonymous access)\n\n### From Command Line\n\n```bash\naz storage container set-permission --name insights-operational-logs --account-name <Storage Account Name> --public-access off\n```\n\n**Note:** By default, public access is set to null (allowing only private access) for a container with activity log export.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_1_3"
        source          = "mage"
        summary         = "The storage account container containing the activity log export should not be publicly accessible.\n\nAllowing public access to activity log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "5.1.4" {
      description = "Azure CIS 5.1.4: Ensure the storage account containing the container with activity logs is encrypted with BYOK (Use Your Own Key)"
      query       = <<EOF
        SELECT subscription_id, id, name
        FROM azure_storage_accounts
        WHERE id IN (SELECT DISTINCT storage_account_id FROM azure_monitor_log_profiles)
              AND (encryption_key_source != 'Microsoft.Keyvault'
                   OR encryption_key_vault_properties_key_name IS NULL)
      EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The storage account with the activity log export container is configured to use BYOK (Use Your Own Key).\n\nConfiguring the storage account with the activity log export container to use BYOK (Use Your Own Key) provides additional confidentiality controls on log data as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK.\n\nBy default, for a storage account keySource is set to `Microsoft.Storage` allowing encryption with vendor Managed key and not the BYOK (Use Your Own Key).\n"
        recommendations = "### From Console\n\n1. In right column, Click service Storage Accounts to access Storage account blade\n2. Click on the storage account name\n3. In Section `Security + networking` click **Encryption**. It will show Storage service encryption configuration pane\n4. In `Encryption selection` check **Customer-managed keys** is selected.\n5. Use option Enter `Key URI`or `Select from Key Vault` to set up encryption with your own key\n\n### From Command Line\n\n```bash\naz storage account update --name <name of the storage account> --resourcegroup <resource group for a storage account> --encryption-keysource=Microsoft Keyvault --encryption-key-vault <Key Valut URI> --encryption-key-name <KeyName> --encryption-key-version <Key Version>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_1_4"
        source          = "mage"
        summary         = "The storage account with the activity log export container is configured to use BYOK (Use Your Own Key).\n\nConfiguring the storage account with the activity log export container to use BYOK (Use Your Own Key) provides additional confidentiality controls on log data as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK.\n\nBy default, for a storage account keySource is set to `Microsoft.Storage` allowing encryption with vendor Managed key and not the BYOK (Use Your Own Key).\n"
      }
    }

    query "5.1.5" {
      description = "Azure CIS 5.1.5: Ensure that logging for Azure KeyVault is 'Enabled'"
      query       = <<EOF
        SELECT v.subscription_id, v.id
        FROM
          azure_keyvault_vaults v
            LEFT OUTER JOIN azure_monitor_diagnostic_settings ds
            ON v.id = ds.resource_uri
            LEFT OUTER JOIN azure_monitor_diagnostic_setting_logs logs
            ON ds.cq_id = logs.diagnostic_setting_cq_id
        WHERE logs.category IS DISTINCT FROM 'AuditEvent'
              OR logs.retention_policy_enabled IS DISTINCT FROM true
              OR logs.retention_policy_days IS NULL
      EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.\n\nMonitoring how and when key vaults are accessed, and by whom enables an audit trail of interactions with confidential information, keys and certificates managed by Azure Keyvault. Enabling logging for Key Vault saves information in an Azure storage account that the user provides. This creates a new container named `insights-logs-auditevent` automatically for the specified storage account, and this same storage account can be used for collecting logs for multiple key vaults.\n"
        recommendations = "Follow Microsoft Azure [documentation](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-logging) and setup Azure Key Vault Logging.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_1_5"
        source          = "mage"
        summary         = "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.\n\nMonitoring how and when key vaults are accessed, and by whom enables an audit trail of interactions with confidential information, keys and certificates managed by Azure Keyvault. Enabling logging for Key Vault saves information in an Azure storage account that the user provides. This creates a new container named `insights-logs-auditevent` automatically for the specified storage account, and this same storage account can be used for collecting logs for multiple key vaults.\n"
      }
    }

    query "5.2.1" {
      description = "Azure CIS 5.2.1: Ensure that Activity Log Alert exists for Create Policy Assignment"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.authorization/policyassignments/write')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.authorization/policyassignments'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        source          = "mage"
        summary         = "Create an activity log alert for the Create Policy Assignment event.\n\nMonitoring for create policy assignment events gives insight into changes done in \"azure policy - assignments\" and can reduce the time it takes to detect unsolicited changes. By default, no monitoring alerts are created.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the Create Policy Assignment event.\n\nMonitoring for create policy assignment events gives insight into changes done in \"azure policy - assignments\" and can reduce the time it takes to detect unsolicited changes. By default, no monitoring alerts are created.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select `Create policy assignment` under signal name\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for Create policy assignment\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n   \"location\":\"Global\",\n   \"tags\":{\n\n   },\n   \"properties\":{\n      \"scopes\":[\n         \"/subscriptions/<Subscription_ID>\"\n      ],\n      \"enabled\":true,\n      \"condition\":{\n         \"allOf\":[\n            {\n               \"containsAny\":null,\n               \"equals\":\"Administrative\",\n               \"field\":\"category\"\n            },\n            {\n               \"containsAny\":null,\n               \"equals\":\"Microsoft.Authorization/policyAssignments/write\",\n               \"field\":\"operationName\"\n            }\n         ]\n      },\n      \"actions\":{\n         \"actionGroups\":[\n            {\n               \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Gr\noup>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n               \"webhookProperties\":null\n            }\n         ]\n      }\n   }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_1"
      }
    }

    query "5.2.2" {
      description = "Azure CIS 5.2.2: Ensure that Activity Log Alert exists for Delete Policy Assignment"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.authorization/policyassignments/delete')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.authorization/policyassignments'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the Create Policy Assignment event.\n\nMonitoring for create policy assignment events gives insight into changes done in \"azure policy - assignments\" and can reduce the time it takes to detect unsolicited changes. By default, no monitoring alerts are created.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select `Create policy assignment` under signal name\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for Create policy assignment\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n   \"location\":\"Global\",\n   \"tags\":{\n\n   },\n   \"properties\":{\n      \"scopes\":[\n         \"/subscriptions/<Subscription_ID>\"\n      ],\n      \"enabled\":true,\n      \"condition\":{\n         \"allOf\":[\n            {\n               \"containsAny\":null,\n               \"equals\":\"Administrative\",\n               \"field\":\"category\"\n            },\n            {\n               \"containsAny\":null,\n               \"equals\":\"Microsoft.Authorization/policyAssignments/write\",\n               \"field\":\"operationName\"\n            }\n         ]\n      },\n      \"actions\":{\n         \"actionGroups\":[\n            {\n               \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Gr\noup>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n               \"webhookProperties\":null\n            }\n         ]\n      }\n   }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_2"
        source          = "mage"
        summary         = "Create an activity log alert for the Create Policy Assignment event.\n\nMonitoring for create policy assignment events gives insight into changes done in \"azure policy - assignments\" and can reduce the time it takes to detect unsolicited changes. By default, no monitoring alerts are created.\n"
      }
    }

    query "5.2.3" {
      description = "Azure CIS 5.2.3: Ensure that Activity Log Alert exists for Create or Update Network Security Group"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/write')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an Activity Log Alert for the \"Create\" or \"Update Network Security Group\" event.\n\nMonitoring for \"Create\" or \"Update Network Security Group\" events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select `Create` or `Update Network Security Group` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\": \"Global\",\n  \"tags\": {},\n  \"properties\": {\n    \"scopes\": [\n      \"/subscriptions/<Subscription_ID>\"\n    ],\n    \"enabled\": true,\n    \"condition\": {\n      \"allOf\": [\n        {\n          \"containsAny\": null,\n          \"equals\": \"Administrative\",\n          \"field\": \"category\"\n        },\n        {\n          \"containsAny\": null,\n          \"equals\": \"Microsoft.Network/networkSecurityGroups/write\",\n          \"field\": \"operationName\"\n        }\n      ]\n    },\n    \"actions\": {\n      \"actionGroups\": [\n        {\n          \"actionGroupId\": \"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Gr oup>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n          \"webhookProperties\": null\n        }\n      ]\n    }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_3"
        source          = "mage"
        summary         = "Create an Activity Log Alert for the \"Create\" or \"Update Network Security Group\" event.\n\nMonitoring for \"Create\" or \"Update Network Security Group\" events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
      }
    }

    query "5.2.4" {
      description = "Azure CIS 5.2.4: Ensure that Activity Log Alert exists for Delete Network Security Group"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/delete')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select `Delete Network Security Group` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\":\"Microsoft.Network/networkSecurityGroups/delete\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_4"
        source          = "mage"
        summary         = "Create an Activity Log Alert for the `Delete Network Security Group` event..\n\nMonitoring for \"Delete Network Security Group\" events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an Activity Log Alert for the `Delete Network Security Group` event..\n\nMonitoring for \"Delete Network Security Group\" events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
      }
    }

    query "5.2.5" {
      description = "Azure CIS 5.2.5: Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/securityrules/write')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/securityrules'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        description     = "Create an activity log alert for the `Create` or `Update Network Security Group Rule` event.\n\nMonitoring for Create or Update Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select  `Create` or `Update Network Security Group Rule` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\":\"Microsoft.Network/networkSecurityGroups/securityRules/write\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_5"
        source          = "mage"
        summary         = "Create an activity log alert for the `Create` or `Update Network Security Group Rule` event.\n\nMonitoring for Create or Update Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "5.2.6" {
      description = "Azure CIS 5.2.6: Ensure that activity log alert exists for the Delete Network Security Group Rule"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/securityrules/delete')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.network/networksecuritygroups/securityrules'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        source          = "mage"
        summary         = "Create an activity log alert for the `Delete Network Security Group` Rule event.\n\nMonitoring for Delete Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the `Delete Network Security Group` Rule event.\n\nMonitoring for Delete Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select  `Delete Network Security Group Rule` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\":\"Microsoft.Network/networkSecurityGroups/securityRules/delete\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_6"
      }
    }

    query "5.2.7" {
      description = "Azure CIS 5.2.7: Ensure that Activity Log Alert exists for Create or Update Security Solution"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.security/securitysolutions/write')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'security')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.security/securitysolutions'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the `Create` or `Update Security Solution` event.\n\nMonitoring for Create or Update Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select   `Create` or `Update Security Solutions` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\":\"Microsoft.Security/securitySolutions/write\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_7"
        source          = "mage"
        summary         = "Create an activity log alert for the `Create` or `Update Security Solution` event.\n\nMonitoring for Create or Update Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "5.2.8" {
      description = "Azure CIS 5.2.8: Ensure that Activity Log Alert exists for Delete Security Solution"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.security/securitysolutions/delete')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'security')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.security/securitysolutions'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the `Delete Security Solution` event.\n\nMonitoring for Delete Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select `Delete Security Solutions` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\": \"Microsoft.Security/securitySolutions/delete\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_8"
        source          = "mage"
        summary         = "Create an activity log alert for the `Delete Security Solution` event.\n\nMonitoring for Delete Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.\n"
      }
    }

    query "5.2.9" {
      description = "Azure CIS 5.2.9: Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule"
      query       = <<EOF
        WITH subs_alerts AS (
          SELECT subs.subscription_id, subs.id, (
                SELECT COUNT(*)
                FROM azure_monitor_activity_log_alerts alerts JOIN azure_monitor_activity_log_alert_conditions conds ON alerts.cq_id = conds.activity_log_alert_cq_id
                WHERE array_position(alerts.scopes, subs.id) IS NOT NULL
                  AND alerts.location = 'Global'
                  AND alerts.enabled
                  AND 
                  ((conds.field = 'operationName' AND LOWER(conds.equals) = 'microsoft.sql/servers/firewallrules/write')
                   OR (conds.field = 'category' AND LOWER(conds.equals) = 'administrative')
                   OR (conds.field = 'resourceType' AND LOWER(conds.equals) = 'microsoft.sql/servers/firewallrules'))
                GROUP BY alerts.id
                HAVING COUNT(*) = 3
                LIMIT 1
          ) as ok
          FROM azure_subscription_subscriptions subs
        )
        SELECT subscription_id, id
        FROM subs_alerts
        WHERE ok IS DISTINCT FROM 3
      EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Create an activity log alert for the `Create` or `Update` or `Delete SQL Server Firewall Rule` event.\n\nMonitoring for Create or Update or Delete SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        recommendations = "### From Console\n\n1. Login to `Azure Monitor` console\n2. Select `Alerts`\n3. Click On **New Alert Rule**\n4. Under Scope, click **Select resource**\n5. Select the appropriate subscription under Filter by `subscription`\n6. Select `Policy Assignment` under **Filter by resource type**\n7. Select `All` for **Filter by location**\n8. Click on the `subscription resource` from the entries populated under `Resource`\n9. Verify Selection preview shows All Policy assignment (policyAssignments) and your selected subscription name\n10. Click **Done**\n11. Under `Condition` section click **Add Condition**\n12. Select  `All Administrative operations` signal\n13. Click **Done**\n14. Under `Action group` in `Actions` section, select **Add action groups** and complete creation process or select appropriate action group\n15. Under `Alert rule details`, enter `Alert rule name` and `Description`\n16. Select appropriate `resource group` to save the alert to\n17. Check `Enable alert rule` upon creation checkbox\n18. Click **Create** alert rule\n\n### From Command Line\n\nUse the below command to create an Activity Log Alert for `Create` or `Update Network Security Groups`\n\n```bash\naz account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" \\\n--out tsv | xargs -L1 bash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \\\n\"Content-Type:application/json\" \\\nhttps://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@\"input.json\"'\n```\n\nWhere input.json contains the Request body JSON data as mentioned below.\n\n```json\n{\n  \"location\":\"Global\",\n  \"tags\":{\n\n  },\n  \"properties\":{\n     \"scopes\":[\n        \"/subscriptions/<Subscription_ID>\"\n     ],\n     \"enabled\":true,\n     \"condition\":{\n        \"allOf\":[\n           {\n              \"containsAny\":null,\n              \"equals\":\"Administrative\",\n              \"field\":\"category\"\n           },\n           {\n              \"containsAny\":null,\n              \"equals\":  \"Microsoft.Sql/servers/firewallRules/write\",\n              \"field\":\"operationName\"\n           }\n        ]\n     },\n     \"actions\":{\n        \"actionGroups\":[\n           {\n              \"actionGroupId\":\"/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>\",\n              \"webhookProperties\":null\n           }\n        ]\n     }\n  }\n}\n```\n\nConfigurable Parameters for command line:\n\n```bash\n<Resource_Group_To Create_Alert_In> <Unique_Alert_Name>\n```\n\nConfigurable Parameters for input.json:\n\n```\n<Subscription_ID> in scopes\n<Subscription_ID> in actionGroupId\n<Resource_Group_For_Alert_Group> in actionGroupId\n<Alert_Group> in actionGroupId\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_5_2_9"
        source          = "mage"
        summary         = "Create an activity log alert for the `Create` or `Update` or `Delete SQL Server Firewall Rule` event.\n\nMonitoring for Create or Update or Delete SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.\n"
        attack_surface  = "CLOUD"
      }
    }
  }

  policy "azure-cis-section-6" {
    description = "Azure CIS Section 6"

    view "azure_nsg_rules" {
      description = "Azure network security groups rules with parsed ports"
      query "azure_nsg_rules_query" {
        query = file("queries/nsg_rules_ports.sql")
      }
    }

    query "6.1" {
      description = "Azure CIS 6.1 Ensure that RDP access is restricted from the internet (Automated)"
      query       = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND (single_port = '3389'
          OR 3389 BETWEEN range_start AND range_end)
      AND protocol = 'Tcp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Disable RDP access on network security groups from the Internet.\n\nThe potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.\n"
        recommendations = "Disable direct RDP access to your Azure Virtual Machines from the Internet. After direct RDP access from the Internet is disabled, you have other options you can use to access these virtual machines for remote management:\n\n1. [Point-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)\n1. [Site-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-site-to-site-resource-manager-portal)\n1. [ExpressRoute](https://docs.microsoft.com/en-us/azure/expressroute/)\n\n**Note:** By default, RDP access from internet is not enabled.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_1"
        source          = "mage"
        summary         = "Disable RDP access on network security groups from the Internet.\n\nThe potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.\n"
        attack_surface  = "CLOUD"
      }
    }


    query "6.2" {
      description = "Azure CIS 6.2 Ensure that SSH access is restricted from the internet (Automated)"
      query       = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND (single_port = '22'
          OR 22 BETWEEN range_start AND range_end)
    EOF
      risk {
        description     = "Disable `SSH` access on network security groups from the Internet.\n\nThe potential security problem with using `SSH` over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.\n"
        recommendations = "Disable direct `SSH` access to your Azure Virtual Machines from the Internet. After direct `SSH` access from the Internet is disabled, you have other options you can use to access these virtual machines for remote management:\n\n1. [Point-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)\n1. [Site-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-site-to-site-resource-manager-portal)\n1. [ExpressRoute](https://docs.microsoft.com/en-us/azure/expressroute/)\n\n**Note:** By default, `SSH` access from internet is not enabled.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_2"
        source          = "mage"
        summary         = "Disable `SSH` access on network security groups from the Internet.\n\nThe potential security problem with using `SSH` over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "6.3" {
      description = "Azure CIS 6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP) (Automated)"
      //todo think about "other combinations which allows access to wider public IP ranges including Windows Azure IP ranges."
      query = <<EOF
      SELECT ass.subscription_id AS subscription_id, ass.id AS server_id, ass."name" AS server_name
      FROM azure_sql_servers ass
      LEFT JOIN
       azure_sql_server_firewall_rules assfr ON
      ass.cq_id = assfr.server_cq_id
      WHERE assfr.start_ip_address = '0.0.0.0'
      OR ( assfr.start_ip_address = '255.255.255.255'
          AND assfr.end_ip_address = '0.0.0.0' );
    EOF
      risk {
        recommendations = "### From Console\n\n1. Login to Azure console, go to SQL servers\n2. For each SQL server\n3. Click on `Firewall / Virtual Networks` under security section from side bar\n4. Set `Allow access to Azure services` to **OFF**\n5. Set firewall rules to limit access to only authorized connections\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_3"
        source          = "mage"
        summary         = "Ensure that no SQL Databases allow ingress from `0.0.0.0/0` (ANY IP).\n\nSQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters.\n\nBy default, for a SQL server, a Firewall exists with `StartIp` of `0.0.0.0` and `EndIP` of `0.0.0.0` allowing access to all the Azure services.\n\nAdditionally, a custom rule can be set up with `StartIp` of `0.0.0.0` and `EndIP` of `255.255.255.255` allowing access from ANY IP over the Internet.\n\nIn order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters.\n\nBy default, setting Allow access to Azure Services is set to ON allowing access to all Windows Azure IP ranges.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Ensure that no SQL Databases allow ingress from `0.0.0.0/0` (ANY IP).\n\nSQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters.\n\nBy default, for a SQL server, a Firewall exists with `StartIp` of `0.0.0.0` and `EndIP` of `0.0.0.0` allowing access to all the Azure services.\n\nAdditionally, a custom rule can be set up with `StartIp` of `0.0.0.0` and `EndIP` of `255.255.255.255` allowing access from ANY IP over the Internet.\n\nIn order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters.\n\nBy default, setting Allow access to Azure Services is set to ON allowing access to all Windows Azure IP ranges.\n"
      }
    }

    query "6.4" {
      description = "Azure CIS 6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' (Automated)"
      query       = <<EOF
      SELECT ansg.subscription_id AS subscription_id, ansg."name" AS nsg_name, ansg.id AS nsg_name, ansgfl.retention_policy_enabled, ansgfl.retention_policy_days
      FROM azure_network_security_groups ansg
      LEFT JOIN azure_network_security_group_flow_logs ansgfl ON
      ansg.cq_id = ansgfl.security_group_cq_id
      WHERE ansgfl.retention_policy_enabled != TRUE
      OR ansgfl.retention_policy_enabled IS NULL
      OR ansgfl.retention_policy_days < 90
      OR ansgfl.retention_policy_days IS NULL;
    EOF
      risk {
        source          = "mage"
        summary         = "Network Security Group Flow Logs should be enabled and the retention period is set to greater than or equal to 90 days.\n\nFlow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches. By default, Network Security Group Flow Logs are disabled.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Network Security Group Flow Logs should be enabled and the retention period is set to greater than or equal to 90 days.\n\nFlow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches. By default, Network Security Group Flow Logs are disabled.\n"
        recommendations = "### From Console\n\n1. Login to Azure console, go to Network Watcher\n2. Select `NSG flow logs` blade in the Logs section\n3. Select each `Network Security Group`from the list\n4. Ensure `Status` is set to **On**\n5. Ensure `Retention (days)` setting greater than `90` days\n6. Select your storage account in the Storage account field\n7. Select **Save**\n\n### From Command Line\n\nEnable the NSG flow logs and set the Retention (days) to greater than or equal to 90 days.\n\n```bash\naz network watcher flow-log configure --nsg <NameorID of the Network SecurityGroup> --enabled true --resource-group <resourceGroupName> --retention 91 -- storage-account <NameorID of the storage account to save flow logs>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_4"
      }
    }

    query "6.5" {
      description   = "Azure CIS 6.5 Ensure that Network Watcher is 'Enabled' (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Enable Network Watcher for Azure subscriptions.\n\nNetwork diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.\n\nNetwork Watcher is automatically enabled. When you create or update a virtual network in your subscription, Network Watcher will be enabled automatically in your Virtual Network's region. There is no impact to your resources or associated charge for automatically enabling Network Watcher.\n\n**Note:** Opting-out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.\n"
        recommendations = "### From Console\n\n1. Go to Network Watcher\n2. Ensure that the `STATUS` is set to `Enabled`\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_5"
        source          = "mage"
        summary         = "Enable Network Watcher for Azure subscriptions.\n\nNetwork diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.\n\nNetwork Watcher is automatically enabled. When you create or update a virtual network in your subscription, Network Watcher will be enabled automatically in your Virtual Network's region. There is no impact to your resources or associated charge for automatically enabling Network Watcher.\n\n**Note:** Opting-out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "6.6" {
      description = "Azure CIS 6.6 Ensure that UDP Services are restricted from the Internet (Automated)"
      query       = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND ((single_port = '53'
          OR 53 BETWEEN range_start AND range_end)
      OR (single_port = '123'
          OR 123 BETWEEN range_start AND range_end)
      OR (single_port = '161'
          OR 161 BETWEEN range_start AND range_end)
      OR (single_port = '389'
          OR 389 BETWEEN range_start AND range_end));
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Disable Internet exposed UDP ports on network security groups.\n\nThe potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification source for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.\n\n**Note:** Opting-out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.\n"
        recommendations = "Disable direct UDP access to your Azure Virtual Machines from the Internet. After direct UDP access from the Internet is disabled, you have other options you can use to access UDP based services running on these virtual machines:\n\n1. [Point-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)\n1. [Site-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-site-to-site-resource-manager-portal)\n1. [ExpressRoute](https://docs.microsoft.com/en-us/azure/expressroute/)\n\n**Note:** By default, UDP access from internet is not enabled.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_6_6"
        source          = "mage"
        summary         = "Disable Internet exposed UDP ports on network security groups.\n\nThe potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification source for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.\n\n**Note:** Opting-out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.\n"
      }
    }
  }

  policy "azure-cis-section-7" {
    description = "Azure CIS Section 7"

    query "7.1" {
      description = "Azure CIS 7.1 Ensure Virtual Machines are utilizing Managed Disks (Manual)"
      query       = <<EOF
      SELECT subscription_id, id, name
      FROM azure_compute_virtual_machines WHERE storage_profile -> 'osDisk' -> 'managedDisk' -> 'id' IS NULL;
    EOF
      risk {
        description     = "Migrate BLOB based VHD's to Managed Disks on Virtual Machines to exploit the default features of this configuration. The features include\n  - Default Disk Encryption\n  - Resilience as Microsoft will managed the disk storage and move around if underlying hardware goes faulty\n  - Reduction of costs over storage accounts\n\nManaged disks are by default encrypted on the underlying hardware so no additional encryption is required for basic protection, it is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM deployed Virtual Machines, Azure Adviser will at some point recommend moving VHD's to managed disks both from a security and cost management perspective.\n"
        recommendations = "### From Console\n\nPerform the following action to check VM are utilizing managed disks:\n\n1. Using the search feature, go to `Virtual Machines`.\n2. From `Manage view`, select `Edit columns`.\n3. Add `Uses managed disks` to the selected columns.\n4. Select `Save`.\n5. Ensure virtual machine listed are using a managed disk. `Uses managed disks` column value is `Yes`.\n\nPerform the following action to add a managed disk to a VM:\n\n1. Using the search feature, go to `Virtual Machines`.\n2. Select the virtual machine you would like to convert\n3. From `Settings` section, select `Disks`.\n4. At the top select `Migrate to managed disks`.\n5. Select `Migrate` to start the process.\n\n**Note** On converting to managed disks VMs will be powered off and back on.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_1"
        source          = "mage"
        summary         = "Migrate BLOB based VHD's to Managed Disks on Virtual Machines to exploit the default features of this configuration. The features include\n  - Default Disk Encryption\n  - Resilience as Microsoft will managed the disk storage and move around if underlying hardware goes faulty\n  - Reduction of costs over storage accounts\n\nManaged disks are by default encrypted on the underlying hardware so no additional encryption is required for basic protection, it is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM deployed Virtual Machines, Azure Adviser will at some point recommend moving VHD's to managed disks both from a security and cost management perspective.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "7.2" {
      description = "Azure CIS 7.2 Ensure that 'OS and Data' disks are encrypted with CMK (Automated)"
      query       = <<EOF
      SELECT v.subscription_id AS subscription_id, v.id AS vm_id , v.name AS vm_name, d.id AS disk_id , d.name AS disk_name, d.encryption_type
      FROM azure_compute_virtual_machines v
      JOIN azure_compute_disks d ON
      LOWER(v.id) = LOWER(d.managed_by)
      AND encryption_type NOT LIKE '%CustomerKey%';
    EOF
      risk {
        description     = "Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK. By encrypting it ensures that the entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. CMK is superior encryption although requires additional planning. You must have your key vault setup to encrypt.\n"
        recommendations = "### From Console\n\nDisks must be detached from VMs to have encryption changed.\n\n1. Go to `Virtual machines`.\n2. For each virtual machine, go to `Settings`.\n3. Click on `Disks`.\n4. Click the `X` to detach the disk from the VM.\n5. Now search for Disks and locate the unattached disk.\n6. Click the disk then select `Encryption`\n7. Change your encryption type, then select your encryption set\n8. Click `Save`.\n9. Go back to the VM and re-attach the disk.\n\n### From PowerShell\n\n```powershell\n$KVRGname = 'MyKeyVaultResourceGroup';\n$VMRGName = 'MyVirtualMachineResourceGroup';\n$vmName = 'MySecureVM';\n$KeyVaultName = 'MySecureVault';\n$KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName\n$KVRGname;\n$diskEncryptionKeyVaultUrl = $KeyVault.VaultUri; $KeyVaultResourceId = $KeyVault.ResourceId;\nSet-AzVMDiskEncryptionExtension -ResourceGroupName $VMRGname -VMName $vmName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl - DiskEncryptionKeyVaultId $KeyVaultResourceId;\n```\n\n**Note**\n- During encryption it is likely that a reboot will be required, it may take up to 15 minutes to complete the process.\n- This may differ for Linux Machines as you may need to set the -skipVmBackup parameter.\n- By default, Azure disks are encrypted using SSE with PMK.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_2"
        source          = "mage"
        summary         = "Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK. By encrypting it ensures that the entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. CMK is superior encryption although requires additional planning. You must have your key vault setup to encrypt.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }

    query "7.3" {
      description = "Azure CIS 7.3 Ensure that 'Unattached disks' are encrypted with CMK (Automated)"
      //todo maybe replace '%CustomerKey%' with 'EncryptionAtRestWithCustomerKey'
      query = <<EOF
      SELECT subscription_id, id AS disk_id, "name" AS disk_name, encryption_type
      FROM azure_compute_disks acd3
      WHERE disk_state = 'Unattached'
      AND encryption_type NOT LIKE '%CustomerKey%';
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Ensure that unattached disks in a subscription are encrypted with a Customer Managed Key (CMK). Managed disks are encrypted by default with Platform-managed keys. Using Customer- managed keys may provide an additional level of security or meet an organization's regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks which may lead to sensitive information disclosure and tampering.\n"
        recommendations = "### From Console\n\n1. Using the search feature, go to `Disks`.\n2. Select the unattached `disk` you would like to encrypt.\n3. From `Settings` section, select `Encryption`.\n4. For the `Encryption type`, select `Encryption at-rest with a customer-managed key`.\n5. Select `Disk encryption set` and click `Save`.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_3"
        source          = "mage"
        summary         = "Ensure that unattached disks in a subscription are encrypted with a Customer Managed Key (CMK). Managed disks are encrypted by default with Platform-managed keys. Using Customer- managed keys may provide an additional level of security or meet an organization's regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks which may lead to sensitive information disclosure and tampering.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "7.4" {
      description = "Azure CIS 7.4 Ensure that only approved extensions are installed (Manual)"
      //      //todo we can list machines extensions names to ease manual check
      //      query = <<EOF
      //      SELECT v.id AS vm_id , v.name AS vm_name, r."name" AS extension_name
      //      FROM azure_compute_virtual_machines v
      //      JOIN azure_compute_virtual_machine_resources r ON
      //      v.cq_id = r.virtual_machine_cq_id
      //    EOF
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Install only organization-approved extensions on VMs. Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented.\n\nBy default, no extensions are added to the virtual machines.\n"
        recommendations = "### From Console\n\nPerform the following action to check approved extensions are installed on a VM:\n\n1. Go to `Virtual machines`.\n2. For each virtual machine, go to `Settings`.\n3. Click on `Extensions`.\n4. Ensure that the listed extensions are approved for use.\n\nPerform the following action to un-install unapproved extensions on a VM:\n\n1. Go to `Virtual machines`.\n2. For each virtual machine, go to `Settings`.\n3. Click on `Extensions`.\n4. If there are any unapproved extensions, uninstall them.\n\n### From Command Line\n\nFrom the check, identify the unapproved extensions, and use the below CLI command to remove an unapproved extension attached to VM\n\n```bash\naz vm extension delete --resource-group <resourceGroupName> --vm-name <vmName> --name <extensionName>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_4"
        source          = "mage"
        summary         = "Install only organization-approved extensions on VMs. Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented.\n\nBy default, no extensions are added to the virtual machines.\n"
        attack_surface  = "CLOUD"
      }
    }


    query "7.5" {
      description   = "Azure CIS 7.5 Ensure that the latest OS Patches for all Virtual Machines are applied (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        criticality     = "INFORMATIONAL"
        description     = "It is recommended the latest OS patches for all virtual machines are applied. The Azure Security Center retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied.\n\nWindows and Linux virtual machines should be kept updated to:\n\n   - Fix a security vulnerability\n   - Improve an OS or application’s general stability\n   - Address a specific bug or flaw\n"
        recommendations = "### From Console\n\nPerform the following action to check latest OS patches are applied on VM:\n\n1. Go to `Security Center - Recommendations`.\n2. Ensure that there are no recommendations available for `Apply system updates`.\n\nFollow Microsoft Azure documentation to apply security patches from the security center - [Security-benchmarks](https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities)\n\n**Note**\n\n- By default, patches are not automatically deployed.\n- You can deploy your own patch assessment and management tool to periodically assess, report and install the required security patches for your OS.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_5"
        source          = "mage"
        summary         = "It is recommended the latest OS patches for all virtual machines are applied. The Azure Security Center retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied.\n\nWindows and Linux virtual machines should be kept updated to:\n\n   - Fix a security vulnerability\n   - Improve an OS or application’s general stability\n   - Address a specific bug or flaw\n"
        attack_surface  = "CLOUD"
      }
    }


    query "7.6" {
      description = "Azure CIS 7.6 Ensure that the endpoint protection for all Virtual Machines is installed (Manual)"
      //todo theoretically we can check if vm has security extensions but user also can have his own security extensions which we can't check
      //      EndpointSecurity || TrendMicroDSA* || Antimalware || EndpointProtection || SCWPAgent || PortalProtectExtension* || FileSecurity*
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        summary         = "It is recommended to install endpoint protection for all virtual machines. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software, with configurable alerts when known malicious or unwanted software attempts to install itself or run on Azure systems.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to install endpoint protection for all virtual machines. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software, with configurable alerts when known malicious or unwanted software attempts to install itself or run on Azure systems.\n"
        recommendations = "### From Console\n\nPerform the following action to check endpoint protection system status:\n\n1. Go to `Security Center - Recommendations`.\n2. Ensure that there are no recommendations available for `Endpoint Protection not installed on Azure VMs`.\n\nFollow Microsoft Azure documentation to install endpoint protection from the security center - [Security-benchmarks-endpoint](https://docs.microsoft.com/en-us/azure/security-center/security-center-install- endpoint-protection)\n\n**Note**\n\n- You can employ your own endpoint protection tool for your OS.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_6"
        source          = "mage"
      }
    }

    query "7.7" {
      description = "Azure CIS 7.7 Ensure that VHD's are encrypted (Manual)"
      query       = <<EOF
      WITH vm_disks AS ( SELECT subscription_id , id, name, jsonb_array_elements( instance_view -> 'disks') AS disk
      FROM azure_compute_virtual_machines), disk_encrytpions AS ( SELECT subscription_id , id, name, disk -> 'name' AS disk_name , (disk -> 'encryptionSettings' -> 0 ->> 'enabled')::boolean AS encryption_enabled
      FROM vm_disks ) SELECT *
      FROM disk_encrytpions
      WHERE encryption_enabled IS NULL
      OR encryption_enabled != TRUE;
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "VHD (Virtual Hard Disks) are stored in BLOB storage and are the old style disks that were attached to Virtual Machines, and the BLOB VHD was then leased to the VM. By Default storage accounts are not encrypted, and Azure Defender(Security Centre) would then recommend that the OS disks should be encrypted. Storage accounts can be encrypted as a whole using PMK or CMK and this should be turned on for storage accounts containing VHD's.\n\nManaged disks that are encrypted by default, we need to also have a recommendation that *legacy* disk that may for a number of reasons need to be left as VHD's should also be encrypted to protect the data content.\n"
        recommendations = "### From Console\n\n1. Navigate to the `storage account` that you need to encrypt.\n2. Select the `encryption` option.\n3. Select the `Encryption type` (Microsoft-managed or Customer-manages key) that you wish to use.\n4. For `Customer-managed`, create or select a key from the key vault and `Save`\n\n### From Command Line\n\nCreate the Keyvault\n```bash\naz keyvault create --name \"myKV\" --resource-group \"myResourceGroup\" -- location eastus --enabled-for-disk-encryption\n```\n\nEncrypt the disk and store the key in keyvault\n```bash\naz vm encryption enable -g MyResourceGroup --name MyVM --disk-encryption- keyvault myKV\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_7_7"
        source          = "mage"
        summary         = "VHD (Virtual Hard Disks) are stored in BLOB storage and are the old style disks that were attached to Virtual Machines, and the BLOB VHD was then leased to the VM. By Default storage accounts are not encrypted, and Azure Defender(Security Centre) would then recommend that the OS disks should be encrypted. Storage accounts can be encrypted as a whole using PMK or CMK and this should be turned on for storage accounts containing VHD's.\n\nManaged disks that are encrypted by default, we need to also have a recommendation that *legacy* disk that may for a number of reasons need to be left as VHD's should also be encrypted to protect the data content.\n"
        attack_surface  = "CLOUD"
      }
    }
  }

  policy "azure-cis-section-8" {
    description = "Azure CIS Section 8"

    query "8.1" {
      description = "Azure CIS 8.1 Ensure that the expiration date is set on all keys (Automated)"
      query       = <<EOF
      SELECT akv.subscription_id AS subscription_id, akv.id AS vault_id, akv."name" AS vault_name, akvk.kid AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_keys akvk ON
            akv.cq_id = akvk.vault_cq_id
      WHERE akvk.kid IS NULL
      OR enabled != TRUE
      OR expires IS NULL;
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended that all keys in Azure Key Vault have an expiration time set. Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration time) attribute identifies the expiration time on or after which the key *MUST NOT* be used for a cryptographic operation.\n\nAs default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration time for all keys.\n"
        recommendations = "### From Console\n\n1. Login and go to `Key vaults`.\n2. For each Key vault, go to `Settings` section and click on `Keys`.\n3. Make sure `Status` is `Enabled`.\n4. Set an appropriate `Expiration Date` on all keys.\n\n### From Command Line\n\nCommand to update the `Expiration Date` for the key\n\n```bash\naz keyvault key set-attributes --name <keyName> --vault-name <vaultName> -- expires Y-m-d'T'H:M:S'Z'\n```\n\n**Note**\n\n- In order to access expiration time on all keys in Azure Key Vault using Microsoft API requires *List* Key permission\n- By default, keys do not expire\n- To provide required access follow below steps\n   - Go to Key vaults\n   - For each Key vault, click on Access Policy\n   - Add access policy with Key permission as `List`\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_8_1"
        source          = "mage"
        summary         = "It is recommended that all keys in Azure Key Vault have an expiration time set. Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration time) attribute identifies the expiration time on or after which the key *MUST NOT* be used for a cryptographic operation.\n\nAs default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration time for all keys.\n"
      }
    }

    query "8.2" {
      description = "Azure CIS 8.2 Ensure that the expiration date is set on all Secrets (Automated)"
      query       = <<EOF
      SELECT akv.subscription_id AS subscription_id, akv.id AS vault_id, akv."name" AS vault_name, akvs.id AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_secrets akvs ON
            akv.cq_id = akvs.vault_cq_id
      WHERE enabled != TRUE
      OR expires IS NULL;
    EOF
      risk {
        summary         = "It is recommended that all *Secrets* in the Azure Key Vault have an expiration time set. The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration time) attribute identifies the expiration time on or after which the secret *MUST NOT* be used.\n\nAs default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration time for all secrets.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended that all *Secrets* in the Azure Key Vault have an expiration time set. The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration time) attribute identifies the expiration time on or after which the secret *MUST NOT* be used.\n\nAs default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration time for all secrets.\n"
        recommendations = "### From Console\n\n1. Login and go to `Key vaults`.\n2. For each Key vault, go to `Settings` section and click on `Secrets`.\n3. Make sure `Status` is `Enabled`.\n4. Set an appropriate `Expiration Date` on all secrets.\n\n### From Command Line\n\nCommand to update the `Expiration Date` for the secret\n\n```bash\naz keyvault secret set-attributes --name <secretName> --vault-name <vaultName> --expires Y-m-d'T'H:M:S'Z'\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_8_2"
        source          = "mage"
      }
    }

    query "8.3" {
      description   = "Azure CIS 8.3 Ensure that Resource Locks are set for mission critical Azure resources (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Resource Manager Locks provide a way for administrators to lock down Azure resources to prevent deletion of, or modifications to, a resource. These locks sit outside of the Role Based Access Controls (RBAC) hierarchy and, when applied, will place restrictions on the resource for all users. These locks are very useful when there is an important resource in a subscription that users should not be able to delete or change. Locks can help prevent accidental and malicious changes or deletion.\n\nThe lock level can be set to to *CanNotDelete* or *ReadOnly* to achieve this purpose.\n   - *CanNotDelete* means authorized users can still read and modify a resource, but they can't delete the resource.\n   - *ReadOnly* means authorized users can read a resource, but they can't delete or update the resource. Applying this lock is similar to restricting all authorized users to the permissions granted by the Reader role.\n\nAs default, no locks are set on the resource.\n"
        recommendations = "### From Console\n\nPerform the following action to check lock is set on the resource:\n\n1. Navigate to the specific Azure Resource or Resource Group.\n2. Click on `Locks`.\n3. Ensure the lock is defined with name and description, type as `CanNotDelete` or `ReadOnly` as appropriate.\n\nPerform the following action to set lock on the resource:\n\n1. Navigate to the specific Azure Resource or Resource Group.\n2. For each of the mission critical resource, click on `Locks`.\n3. Click `Add`.\n4. Give the lock a name and a description, then select the type, `CanNotDelete` or `ReadOnly` as appropriate.\n\n### From Command Line\n\nTo lock a resource, provide the name of the resource, its resource type, and its resource group name.\n\n```bash\naz lock create --name <LockName> --lock-type <CanNotDelete/Read-only> -- resource-group <resourceGroupName> --resource-name <resourceName> --resource- type <resourceType>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_8_3"
        source          = "mage"
        summary         = "Resource Manager Locks provide a way for administrators to lock down Azure resources to prevent deletion of, or modifications to, a resource. These locks sit outside of the Role Based Access Controls (RBAC) hierarchy and, when applied, will place restrictions on the resource for all users. These locks are very useful when there is an important resource in a subscription that users should not be able to delete or change. Locks can help prevent accidental and malicious changes or deletion.\n\nThe lock level can be set to to *CanNotDelete* or *ReadOnly* to achieve this purpose.\n   - *CanNotDelete* means authorized users can still read and modify a resource, but they can't delete the resource.\n   - *ReadOnly* means authorized users can read a resource, but they can't delete or update the resource. Applying this lock is similar to restricting all authorized users to the permissions granted by the Reader role.\n\nAs default, no locks are set on the resource.\n"
      }
    }

    query "8.4" {
      description = "Azure CIS 8.4 Ensure the key vault is recoverable (Automated)"
      query       = <<EOF
      SELECT subscription_id, id, "name", enable_purge_protection
      FROM azure_keyvault_vaults akv
      WHERE enable_soft_delete != TRUE
      OR enable_purge_protection != TRUE;
    EOF
      risk {
        summary         = "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification etc.) supported by the key vault objects.\n\nIt is recommended that the key vault be made recoverable by enabling the *Do Not Purge* and *Soft Delete* functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects , as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\n\nThere are 2 key vault properties that plays role in permanent unavailability of a key vault.\n   - enableSoftDelete: Setting this parameter to true for a key vault ensures that even if key vault is deleted, Key vault itself or its objects remain recoverable for next 90days.\n   - enablePurgeProtection: Setting enablePurgeProtection to *true* ensures that the key vault and its objects cannot be purged.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification etc.) supported by the key vault objects.\n\nIt is recommended that the key vault be made recoverable by enabling the *Do Not Purge* and *Soft Delete* functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects , as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\n\nThere are 2 key vault properties that plays role in permanent unavailability of a key vault.\n   - enableSoftDelete: Setting this parameter to true for a key vault ensures that even if key vault is deleted, Key vault itself or its objects remain recoverable for next 90days.\n   - enablePurgeProtection: Setting enablePurgeProtection to *true* ensures that the key vault and its objects cannot be purged.\n"
        recommendations = "### From Console\n\n1. Login and go to `Key vaults`.\n2. Go to `Settings` section and click on `Properties`.\n3. Select `Enable purge protection` and `Save`.\n\nAs default `Soft-delete` is enabled for a key vault.\n\n### From Command Line\n\nCommand to enabled *Do Not Purge* and *Soft Delete* for a Key Vault\n\n```bash\naz resource update --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx- xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault /vaults/<keyVaultName> --set properties.enablePurgeProtection=true properties.enableSoftDelete=true\n```\n\n**Note** Once purge-protection and soft-delete is enabled for a key vault, the action is irreversible.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_8_4"
        source          = "mage"
      }
    }

    query "8.5" {
      description = "Azure CIS 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services (Automated)"
      query       = <<EOF
      SELECT subscription_id, id, "name", enable_rbac
      FROM azure_container_managed_clusters acmc
      WHERE enable_rbac != TRUE;
    EOF
      risk {
        source          = "mage"
        summary         = "It is recommended to enable RBAC on all Azure Kubernetes Services Instances. Azure Kubernetes Services has the capability to integrate Azure Active Directory users and groups into Kubernetes RBAC controls within the AKS Kubernetes API Server. This should be utilized to enable granular access to Kubernetes resources within the AKS clusters supporting RBAC controls not just of the overarching AKS instance but also the individual resources managed within Kubernetes.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "It is recommended to enable RBAC on all Azure Kubernetes Services Instances. Azure Kubernetes Services has the capability to integrate Azure Active Directory users and groups into Kubernetes RBAC controls within the AKS Kubernetes API Server. This should be utilized to enable granular access to Kubernetes resources within the AKS clusters supporting RBAC controls not just of the overarching AKS instance but also the individual resources managed within Kubernetes.\n"
        recommendations = "As default, RBAC is enabled. This setting cannot be changed after AKS deployment, cluster will require recreation. For more information refer [Use Azure RBAC for Kubernetes](https://docs.microsoft.com/en-us/azure/aks/manage-azure-rbac)\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_8_5"
      }
    }
  }


  policy "azure-cis-section-9" {
    description = "Azure CIS Section 9"

    query "9.1" {
      description = "Azure CIS 9.1 Ensure App Service Authentication is set on Azure App Service (Automated)"
      query       = <<EOF
        SELECT awa.subscription_id,
        awa.id AS app_id, awa."name" AS app_name, awaas.enabled AS auth_enabled
        FROM azure_web_apps awa
        LEFT JOIN azure_web_app_auth_settings awaas ON
        awa.cq_id = awaas.app_cq_id
        WHERE awaas.enabled IS NULL
        OR awaas.enabled != TRUE;
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.\n\nBy enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider(Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers.\n"
        recommendations = "### From Console\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Authentication(classic)`.\n4. Set `App Service Authentication` to `On`.\n5. Choose other parameters as per your requirement and click on `Save`.\n\n### From Command Line\n\nTo set App Service Authentication for an existing app, run the following command:\n\n```bash\naz webapp auth update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --enabled true\n```\n\n**Note**\n\n- In order to access `App Service Authentication` settings for Web app using Microsoft API requires `Website Contributor` permission at subscription level. A custom role can be created in place of website contributor to provide more specific permission and maintain the principle of least privileged access.\n- By default, App Service Authentication is disabled.\n- If you need more flexibility than App Service provides, you can also write your own utilities. Secure authentication and authorization require deep understanding of security, including federation, encryption, JSON web tokens (JWT) management, grant types, and so on.\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_1"
        source          = "mage"
        summary         = "Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.\n\nBy enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider(Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "9.2" {
      description = "Azure CIS 9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service (Automated)"
      query       = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, https_only
        FROM azure_web_apps
        WHERE https_only IS NULL
        OR https_only != TRUE;
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.\n\nEnabling HTTPS-only traffic will redirect all non-secure HTTP request to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated. So it is important to support HTTPS for the security benefits.\n\nAs default, HTTPS-only feature is disabled.\n"
        recommendations = "### From Console\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `TLS/SSL settings`.\n4. Under `Protocol Settings`, set `HTTPS Only` to `On`.\n\n### From Command Line\n\nTo set HTTPS-only traffic value for an existing app, run the following command:\n\n```bash\naz webapp update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> -- set httpsOnly=true\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_2"
        source          = "mage"
        summary         = "Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.\n\nEnabling HTTPS-only traffic will redirect all non-secure HTTP request to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated. So it is important to support HTTPS for the security benefits.\n\nAs default, HTTPS-only feature is disabled.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "9.3" {
      description = "Azure CIS 9.3 Ensure web app is using the latest version of TLS encryption (Automated)"
      query       = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, site_config -> 'minTlsVersion' AS min_tls_version
        FROM azure_web_apps
        WHERE site_config -> 'minTlsVersion' IS NULL
        OR site_config -> 'minTlsVersion' != '1.2';
    EOF
      risk {
        recommendations = "### From Console\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `TLS/SSL settings`.\n4. Under `Protocol Settings`, set `Minimum TLS Version` to `1.2`.\n\n### From Command Line\n\nTo set TLS Version for an existing app, run the following command:\n\n```bash\naz webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --min-tls-version 1.2\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_3"
        source          = "mage"
        summary         = "The TLS(Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows *TLS 1.2* by default, which is the recommended TLS level by industry standards, such as PCI DSS.\n\nIt is highly recommended to use the latest *TLS 1.2* version for web app secure connections. App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2.\n\nAs default, TLS Version feature will be set to 1.2.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "The TLS(Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows *TLS 1.2* by default, which is the recommended TLS level by industry standards, such as PCI DSS.\n\nIt is highly recommended to use the latest *TLS 1.2* version for web app secure connections. App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2.\n\nAs default, TLS Version feature will be set to 1.2.\n"
      }
    }

    query "9.4" {
      description = "Azure CIS 9.4 Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On' (Automated)"
      query       = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, client_cert_enabled
        FROM azure_web_apps
        WHERE client_cert_enabled IS NULL
        OR client_cert_enabled != TRUE;
    EOF
      risk {
        summary         = "Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled, then only an authenticated client who has valid certificates can access the app.\n\nAs default, incoming client certificates is set to *Ignore*.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled, then only an authenticated client who has valid certificates can access the app.\n\nAs default, incoming client certificates is set to *Ignore*.\n"
        recommendations = "### From Console\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Set the option `Client certificate mode` located under `Incoming client certificates` is set to `Require`.\n\n### From Command Line\n\nTo set Incoming client certificates value for an existing app:\n\n```bash\naz webapp update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> -- set clientCertEnabled=true\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_4"
        source          = "mage"
      }
    }

    query "9.5" {
      description = "Azure CIS 9.5 Ensure that Register with Azure Active Directory is enabled on App Service (Automated)"
      query       = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, identity_principal_id
        FROM azure_web_apps
        WHERE identity_principal_id IS NULL
        OR identity_principal_id = '';
    EOF
      risk {
        criticality     = "INFORMATIONAL"
        description     = "Managed service identity in App Service makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings. When registering with *Azure Active Directory* in the app service, the app will connect to other Azure services securely without the need of username and passwords.\n\nApp Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.\n"
        recommendations = "### From Console\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Identity`.\n4. From `System assigned` tab, set `Status` to `On`.\n5. Click `Save`.\n\n### From Command Line\n\nTo set Register with Azure Active Directory feature for an existing app, run the following command:\n\n```bash\naz webapp identity assign --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_5"
        source          = "mage"
        summary         = "Managed service identity in App Service makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings. When registering with *Azure Active Directory* in the app service, the app will connect to other Azure services securely without the need of username and passwords.\n\nApp Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.\n"
        attack_surface  = "CLOUD"
      }
    }

    query "9.6" {
      description = "Azure CIS 9.6 Ensure that 'PHP version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show php version to ease check process
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Periodically newer versions are released for PHP software either due to security flaws or to include additional functionality. Using the latest PHP version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
        recommendations = "### From Console\n\nPerform the following action to check latest version installed:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, ensure `PHP version` is set to latest version.\n\n**Note** No action is required If Stack is not using PHP, as it is not used by your web app.\n\nPerform the following action to install latest version:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, set `PHP version` to the latest version.\n6. Click `Save`.\n\n### From Command Line\n\nTo see the list of supported runtimes:\n\n```bash\naz webapp list-runtimes | grep php\n```\n\nTo set latest PHP version for an existing app, run the following command:\n\n```bash\naz webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --php-version <VERSION>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_6"
        source          = "mage"
        summary         = "Periodically newer versions are released for PHP software either due to security flaws or to include additional functionality. Using the latest PHP version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
      }
    }

    query "9.7" {
      description = "Azure CIS 9.7 Ensure that 'Python version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        summary         = "Periodically, newer versions are released for *Python software* either due to security flaws or to include additional functionality. Using the latest Python version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Periodically, newer versions are released for *Python software* either due to security flaws or to include additional functionality. Using the latest Python version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
        recommendations = "### From Console\n\nPerform the following action to check latest version installed:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, ensure `Python Version` is set to latest version.\n\n**Note** No action is required, If Stack is not using Python, as it is not used by your web app.\n\nPerform the following action to install latest version:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, set `Python Version` to the latest version.\n6. Click `Save`.\n\n### From Command Line\n\nTo see the list of supported runtimes:\n\n```bash\naz webapp list-runtimes | grep python\n```\n\nTo set latest Python version for an existing app, run the following command:\n\n```bash\naz webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --python-version <VERSION>\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_7"
        source          = "mage"
      }
    }

    query "9.8" {
      description = "Azure CIS 9.8 Ensure that 'Java version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        source          = "mage"
        summary         = "Periodically, newer versions are released for Java software either due to security flaws or to include additional functionality. Using the latest Java version for web apps is recommended in order to take advantage of security fixes, if any, and/or new functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Periodically, newer versions are released for Java software either due to security flaws or to include additional functionality. Using the latest Java version for web apps is recommended in order to take advantage of security fixes, if any, and/or new functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n"
        recommendations = "### From Console\n\nPerform the following action to check latest version installed:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, ensure `Java version` is set to latest version.\n\n**Note** No action is required, If Stack is not using Java, as it is not used by your web app.\n\nPerform the following action to install latest version:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Stack settings`, set `Java version` to the latest version.\n6. Set `Java minor version` to latest version available.\n7. Set `Java web server` to latest version available.\n8. Set `Java web server version` to latest version available.\n9. Click `Save`.\n\n### From Command Line\n\nTo see the list of supported runtimes:\n\n```bash\naz webapp list-runtimes | grep java\n```\n\nTo set latest Java version for an existing app, run the following command:\n\n```bash\naz webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --java-version '1.8' --java-container 'Tomcat' --java-container-version '<VERSION>'\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_8"
      }
    }


    query "9.9" {
      description = "Azure CIS 9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n\nHTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.\n"
        recommendations = "### From Console\n\nPerform the following action to check latest version installed:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Platform settings`, ensure `HTTP version` is set to `0.2`.\n\n**Note** Most modern browsers support HTTP 2.0 protocol over TLS only, while non- encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.\n\nPerform the following action to install latest version:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Platform settings`, set `HTTP version` to the latest `0.2`.\n6. Click `Save`.\n\n### From Command Line\n\nTo set HTTP 2.0 version for an existing app, run the following command:\n\n```bash\naz webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --http20-enabled true\n```\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_9"
        source          = "mage"
        summary         = "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.\n\nNewer versions may contain security enhancements and additional functionality. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.\n\nHTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.\n"
      }
    }

    query "9.10" {
      description = "Azure CIS 9.10 Ensure FTP deployments are disabled (Automated)"
      query       = <<EOF
      SELECT subscription_id,
        id AS app_id, "name" AS app_name, identity_principal_id, p.user_name
      FROM azure_web_apps a
      LEFT JOIN azure_web_app_publishing_profiles p ON
      a.cq_id = p.app_cq_id
      WHERE p.user_name NOT like concat('%',a."name", '%')
    EOF
      risk {
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
        description     = "By default, Azure Functions, Web and API Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Service Apps and Functions. Azure FTP deployment endpoints are public.\n\nAn attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear- text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.\n"
        recommendations = "### From Console\n\nFor Web Apps:\n\n1. Login to Azure Portal and go to `App Services`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Platform settings`, select `FTP state` to `Disabled` or `FTPS only`.\n6. Click `Save`.\n\nFor Function Apps:\n\n1. Login to Azure Portal and go to `Function App`.\n2. Click on each App.\n3. Under `Settings` section, click on `Configuration`.\n4. Go to `General settings` tab.\n5. Under `Platform settings`, select `FTP state` to `Disabled` or `FTPS only`.\n6. Click `Save`.\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_10"
        source          = "mage"
        summary         = "By default, Azure Functions, Web and API Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Service Apps and Functions. Azure FTP deployment endpoints are public.\n\nAn attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear- text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.\n"
      }
    }

    query "9.11" {
      description   = "Azure CIS 9.11 Ensure Azure Keyvaults are used to store secrets (Manual)"
      query         = file("queries/manual.sql")
      expect_output = true
      risk {
        description     = "Encryption keys ,Certificate thumbprints and Managed Identity Credentials can be coded into the APP service, this renders them visible as part of the configuration, to maintain security of these keys it is better to store in an Azure Keyvault and reference them from the Keyvault.\n\nApp secrets control access to the application and thus need to be secured externally to the app configuration, storing the secrets externally and referencing them in the configuration also enables key rotation without having to redeploy the app service.\n"
        recommendations = "### From Console\n\nIt has 2 steps process\n\n1. Setup keyvault.\n2. Setup the app service to use keyvault.\n\nFor more information, refer guide for [Key Vault references for App service and functions](https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references)\n\n\n"
        references      = "- https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.cis_v130_9_11"
        source          = "mage"
        summary         = "Encryption keys ,Certificate thumbprints and Managed Identity Credentials can be coded into the APP service, this renders them visible as part of the configuration, to maintain security of these keys it is better to store in an Azure Keyvault and reference them from the Keyvault.\n\nApp secrets control access to the application and thus need to be secured externally to the app configuration, storing the secrets externally and referencing them in the configuration also enables key rotation without having to redeploy the app service.\n"
        attack_surface  = "CLOUD"
        criticality     = "INFORMATIONAL"
      }
    }
  }
}
