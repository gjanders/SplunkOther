# SplunkOther Application
This application has not been published to SplunkBase as I suspect the audience may be too small. Feel free to raise an issue if you would like to see this on SplunkBase

The application itself is very simple, it has 2 dashboards:
-  appadmins
-  dispatch_ttl_changer

# Dashboards
## AppAdmins
The application admins dashboard (appadmins) is a simpleXML dashboard that helps users without admin level privileges share a dashboard/report or similar knowledge object by either cloning it or moving it to the application level of sharing.

This is useful if not everyone has write access within applications in Splunk (thus the "app admin" concept)

## Dispatch TTL changer
This dashboard exists to change the time to live on any Splunk search. Due to complexities in how a Splunk alerts TTL works you may have a search that stays for 2p (two times the run period, for example an hourly search is kept for 2 hours), that in other cases is kept for 24 hours (due to an email action firing)

This TTL changer exists so an average user can easily change this to, for example, 60 seconds in all cases irrelevant of action fired.

Since the average user in Splunk 9.1.3 cannot see the advanced view they have access to update these settings but need to use the REST API, this dashboard allows them to do this via a dashboard

# Commmands
- listdispatchttl - lists only the dispatch.ttl value, not used in the dashboards
- listdispatchttlall - lists all available TTL values found for a savedsearch
- changedispatchttl - sets the dispatch.ttl to the new value for any savedsearch if the logged in user has an admin role. If the user is not an admin it will change only the users searches or throw an error, not used in the dashboards
- changedispatchttlall - sets all dispatch ttl values to the new value for any savedsearch if the logged in user has an admin role. If the user is not an admin it will change only the users searches or throw an error
- listprivateobjects - used by the app admins dashboard to list all private objects of types: views, field extractions, field transforms, savedsearches, macros and datamodels
- shareprivateobjects - changes the sharing of the private object to app level based on the parameters passed in. This includes cloning, reown, overwrite which are set by the appadmins dashboard 
