/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.fakebelieve.henplus.plugins.login;

import henplus.AbstractCommand;
import henplus.Command;
import henplus.CommandDispatcher;
import henplus.HenPlus;
import henplus.SQLSession;
import henplus.SessionManager;
import henplus.commands.ConnectCommand;
import henplus.view.Column;
import henplus.view.ColumnMetaData;
import henplus.view.TableRenderer;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.SortedMap;
import java.util.StringTokenizer;

/**
 *
 * @author mock
 */
public class LoginCommand extends AbstractCommand {

    private final ConnectCommand _connectCommand;
    private final SessionManager _sessionManager;
    private final SortedMap _knownUrls;
    private final HenPlus _henplus;
    private final Field currentSessionNameField;
    private final Method createSessionNameMethod;
    private final List<Credential> credentials = new ArrayList<Credential>();
    private final static ColumnMetaData[] LIST_META;
    private String masterPassword = null;
    private PasswordEncryptionUtil encryptor = null;
    private File passwordFile;
    public static final String CMD_LOGIN = "login";
    public static final String CMD_SET_CRED = "set-credential";
    public static final String CMD_REMOVE_CRED = "remove-credential";
    public static final String CMD_LIST_CREDS = "list-credentials";

    static {
        LIST_META = new ColumnMetaData[4];
        LIST_META[0] = new ColumnMetaData("alias");
        LIST_META[1] = new ColumnMetaData("url");
        LIST_META[2] = new ColumnMetaData("user");
        LIST_META[3] = new ColumnMetaData("password");
    }

    @Override
    public String[] getCommandList() {
        return new String[]{
                    CMD_LOGIN, CMD_LIST_CREDS, CMD_SET_CRED, CMD_REMOVE_CRED
                };
    }

    public LoginCommand() {
        _henplus = HenPlus.getInstance();

        //
        // Strategy here is to find the built-in connect command, and call into it
        // to use its login functions so that we aren't managing sessions in multiple
        // places.
        //
        // In order to do that, we need access to some private methods and fields,
        // so we'll use reflection to get handles to them and call them.
        //

        ConnectCommand connectCommand = null;
        for (Iterator iterator = _henplus.getDispatcher().getRegisteredCommands(); iterator.hasNext();) {
            Command command = (Command) iterator.next();
            if (command instanceof ConnectCommand) {
                connectCommand = (ConnectCommand) command;
                break;
            }
        }

        _connectCommand = connectCommand;

        try {
            Field f = _connectCommand.getClass().getDeclaredField("_sessionManager");
            f.setAccessible(true);
            _sessionManager = (SessionManager) f.get(_connectCommand);

            f = _connectCommand.getClass().getDeclaredField("_knownUrls");
            f.setAccessible(true);
            _knownUrls = (SortedMap) f.get(_connectCommand);

            currentSessionNameField = _connectCommand.getClass().getDeclaredField("currentSessionName");
            currentSessionNameField.setAccessible(true);

            createSessionNameMethod = _connectCommand.getClass().getDeclaredMethod("createSessionName", SQLSession.class, String.class);
            createSessionNameMethod.setAccessible(true);

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

        File file = new File(_henplus.getConfigurationDirectoryInfo());
        passwordFile = new File(file, "passwords");
    }

    protected void loadMasterPassword() {
        if (masterPassword == null) {
            masterPassword = promptPassword("Enter Master Password: ");
            encryptor = new PasswordEncryptionUtil(masterPassword);
        }
    }

    protected void loadCredentials() {
        loadMasterPassword();

        if (!credentials.isEmpty()) {
            return;
        }

        if (!passwordFile.exists()) {
            return;
        }
        try {
            BufferedReader in = new BufferedReader(new FileReader(passwordFile));
            credentials.clear();
            String line;
            while ((line = in.readLine()) != null) {
                StringTokenizer st = new StringTokenizer(line, "||");
                Credential credential = new Credential();
                credential.setAlias(st.nextToken());
                credential.setUrl(st.nextToken());
                credential.setUser(st.nextToken());
                credential.setPassword(encryptor.decrypt(st.nextToken()));

                credentials.add(credential);
            }
            in.close();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } catch (GeneralSecurityException ex) {
            masterPassword = null;
            throw new RuntimeException(ex);
        }

    }

    protected void saveCredentials() {
        loadMasterPassword();

        if (credentials.isEmpty()) {
            return;
        }
        try {
            BufferedWriter out = new BufferedWriter(new FileWriter(passwordFile));
            for (Credential credential : credentials) {
                out.append(credential.getAlias()).append("||");
                out.append(credential.getUrl()).append("||");
                out.append(credential.getUser()).append("||");
                out.append(encryptor.encrypt(credential.getPassword())).append("\n");
            }
            out.close();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }


    }

    protected Credential getCredential(String alias) {
        loadCredentials();

        for (Credential credential : credentials) {
            if (credential.getAlias().equals(alias)) {
                return credential;
            }
        }
        return null;
    }

    protected Credential getCredential(String url, String user) {
        loadCredentials();

        for (Credential credential : credentials) {
            if (credential.getUrl().equals(url) && credential.getUser().equals(user)) {
                return credential;
            }
        }
        return null;
    }

    private void updateCredential(String alias, String url, String user, String password) {
        loadCredentials();

        Credential update = getCredential(alias);

        if (update == null) {
            update = new Credential();
            update.setAlias(alias);
            update.setUrl(url);
            update.setUser(user);
            credentials.add(update);
        }

        update.setPassword(password);
        saveCredentials();
    }

    private void removeCredential(String alias) {
        loadCredentials();

        for (int idx = 0; idx < credentials.size(); idx++) {
            if (credentials.get(idx).getAlias().equals(alias)) {
                credentials.remove(idx);
                break;
            }
        }
        saveCredentials();
    }

    @Override
    public int execute(SQLSession currentSession, String cmd, String param) {
        SQLSession session = null;

        StringTokenizer st = new StringTokenizer(param);
        int argc = st.countTokens();

        if (CMD_LOGIN.equals(cmd)) {
            if (argc < 1 || argc > 2) {
                return SYNTAX_ERROR;
            }
            String credAlias = (String) st.nextElement();
            String alias = (argc == 2) ? st.nextToken() : null;
            Credential credential = getCredential(credAlias);
            if (credential == null) {
                HenPlus.msg().println("Could not find login alias.");
                return EXEC_FAILED;
            }

            String url = credential.getUrl();

            if (alias == null) {
                /*
                 * we only got one parameter. So the that single parameter
                 * might have been an alias. let's see..
                 */
                if (_knownUrls.containsKey(url)) {
                    String possibleAlias = url;
                    url = (String) _knownUrls.get(url);
                    if (!possibleAlias.equals(url)) {
                        alias = possibleAlias;
                    }
                }
            }
            try {
                if (credential != null) {
                    session = new SQLSession(url, credential.getUser(), credential.getPassword());
                } else {
                    session = new SQLSession(url, null, null);
                }
                _knownUrls.put(url, url);
                if (alias != null) {
                    _knownUrls.put(alias, url);
                }
                setCurrentSessionName(createSessionName(session, alias));
                _sessionManager.addSession(getCurrentSessionName(), session);
                _sessionManager.setCurrentSession(session);
            } catch (Exception e) {
                HenPlus.msg().println(e.toString());
                return EXEC_FAILED;
            }
        } else if (CMD_LIST_CREDS.equals(cmd)) {
            loadCredentials();

            String opt = (argc > 0) ? st.nextToken() : null;

            boolean showPasswords = (opt != null && opt.equals("-p"));

            LIST_META[0].resetWidth();
            LIST_META[1].resetWidth();
            LIST_META[2].resetWidth();
            LIST_META[3].resetWidth();
            TableRenderer table = new TableRenderer(LIST_META, HenPlus.out());
            for (Credential credential : credentials) {
                Column[] row = new Column[4];
                row[0] = new Column(credential.getAlias());
                row[1] = new Column(credential.getUrl());
                row[2] = new Column(credential.getUser());
                row[3] = new Column(showPasswords ? credential.getPassword() : "*****");
                table.addRow(row);
            }
            table.closeTable();
            return SUCCESS;
        } else if (CMD_SET_CRED.equals(cmd)) {
            if (argc != 3) {
                return SYNTAX_ERROR;
            }

            String alias = st.nextToken();
            String url = st.nextToken();
            String user = st.nextToken();
            String password = promptPassword("Password: ");

            updateCredential(alias, url, user, password);
            return SUCCESS;
        } else if (CMD_REMOVE_CRED.equals(cmd)) {
            if (argc != 1) {
                return SYNTAX_ERROR;
            }

            String alias = st.nextToken();

            removeCredential(alias);
            return SUCCESS;
        }

        if (getCurrentSessionName() != null) {
            _henplus.setPrompt(getCurrentSessionName() + "> ");
        } else {
            _henplus.setDefaultPrompt();
        }
        _henplus.setCurrentSession(session);

        return SUCCESS;
    }

    protected String promptPassword(String prompt) {

        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }

        char passwordArray[] = console.readPassword(prompt);

        return new String(passwordArray);
    }

    /**
     * Get the CurrentSessionName from the ConnectCommand.
     *
     * Uses reflection to get the current session name from the built-in
     * ConnectCommand.
     *
     * @return
     */
    protected String getCurrentSessionName() {
        try {
            return (String) currentSessionNameField.get(_connectCommand);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        } catch (IllegalAccessException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Set the current session name in the ConnectCommand
     *
     * Uses reflection to set the current session name in the built-in
     * ConnectCommand.
     *
     * @param value
     */
    protected void setCurrentSessionName(String value) {
        try {
            currentSessionNameField.set(_connectCommand, value);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        } catch (IllegalAccessException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Create a unique session name
     *
     * Uses reflection to call into the ConnectCommand's createSessionName()
     * method to create a unique session name.
     *
     * @param session
     * @param alias
     * @return
     */
    protected String createSessionName(SQLSession session, String alias) {
        try {
            return (String) createSessionNameMethod.invoke(_connectCommand, session, alias);
        } catch (IllegalAccessException ex) {
            throw new RuntimeException(ex);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        } catch (InvocationTargetException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * None of our commands require a valid session.
     */
    @Override
    public boolean requiresValidSession(String cmd) {
        return false;
    }
    /*
     * (non-Javadoc)
     * @see henplus.Command#isComplete(java.lang.String)
     */

    @Override
    public boolean isComplete(String command) {
        return true;
    }

    @Override
    public String getShortDescription() {
        return "login using stored credentials";
    }

    @Override
    public String getSynopsis(String cmd) {
        if (CMD_LOGIN.equals(cmd)) {
            return CMD_LOGIN + " <alias>";
        }
        if (CMD_LIST_CREDS.equals(cmd)) {
            return CMD_LIST_CREDS;
        }
        if (CMD_SET_CRED.equals(cmd)) {
            return CMD_SET_CRED + " <alias> <url> <user>";
        }
        if (CMD_REMOVE_CRED.equals(cmd)) {
            return CMD_REMOVE_CRED + " <alias>";
        }

        return "";
    }

    /*
     * (non-Javadoc)
     * @see henplus.Command#getLongDescription(java.lang.String)
     */
    @Override
    public String getLongDescription(String cmd) {
        return "\tCreate and use login aliases with credentials.\n"
                + "\n"
                + "\tTo create or update an aliased credential:\n"
                + "\t\tset-credential <alias> <url> <user>\n"
                + "\t\t* You will be prompted to set a password\n\n"
                + "\tTo remove an aliased credential:\n"
                + "\t\tremove-credential <alias>\n\n"
                + "\tTo list credentials:\n"
                + "\t\tlist-credentials\n\n"
                + "\tTo connect using an aliased credential:\n"
                + "\t\tlogin <alias>\n\n"
                + "\t* Credentials are encrypted for storage";
    }

    /*
     * (non-Javadoc)
     * @see henplus.Command#participateInCommandCompletion()
     */
    @Override
    public boolean participateInCommandCompletion() {
        return true;
    }

    /**
     * Offer command completion.
     *
     * For the "login" and "remove-credential" commands offer the known
     * aliases to auto complete with.
     *
     * @param disp
     * @param partialCommand
     * @param lastWord
     * @return
     */
    @Override
    public Iterator complete(CommandDispatcher disp, String partialCommand, String lastWord) {

        List<String> aliases = new ArrayList<String>();

        if (masterPassword != null) {
            if (partialCommand.startsWith(CMD_LOGIN) || partialCommand.startsWith(CMD_REMOVE_CRED)) {
                loadCredentials();
                for (Credential credential : credentials) {
                    if (credential.getAlias().startsWith(lastWord)) {
                        aliases.add(credential.getAlias());
                    }
                }
            }
        }

        return aliases.iterator();
    }
}
