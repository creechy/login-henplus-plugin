##Login Henplus Plug-In##

This plugin allows you to manage connection settings with credentials and use them to connect to databases.

###Easy Setup###

Simply put `login-henplus-plugin.jar` in to the CLASSPATH of `henplus`, generally in the `share/henplus` folder somewhere.

Start `henplus` and register the plugin. Use the `plug-in` command for this. This only needs to be done once, and will be persisted.

     Hen*Plus> plug-in org.fakebelieve.henplus.plugins.LoginCommand

###Usage###

The plugin responds to four commands `login`, `set-credential`, `remove-credential` and `list-credentials`.

*Creating and updating connection settings with the `set-credential` command*

The `set-credential` command takes four parameters: `<alias>` `<url>` `<username>` `<password>`

*Removing connection settings with the `remove-credential` command*

The `remove-credential` command takes one parameter: `<alias>`

*Listing all connection settings with the `list-credentials` command*

The `list-credentials` command takes an optional parameter: `-p`

*Connecting using the `login` command*

The `login` command takes one parameter: `<alias>`


