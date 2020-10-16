'''
Git Bridge extension for Burp Suite Pro

The Git Bridge plugin lets Burp users store and share findings and other Burp 
items via git. Users can right-click supported items in Burp to send them to
a git repo and use the Git Bridge tab to send items back to their respective 
Burp tools.

For more information see https://github.com/mateodurante/burp-git-bridge.

This extension is a PoC. Right now only Repeater and Scanner are supported, 
and the code could use refactoring. If you're interested in a more polished 
version or more features let me know, or better yet consider sending me a pull request. 

Thanks for checking it out.

Writer: Jonathan Foote 2015-04-21
Editor: Mateo Durante 2020-10-15

This project needs:
 - git
 - xdotools
'''

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IScanIssue, IHttpService, IHttpRequestResponse, IBurpExtenderCallbacks
from java.awt import Component
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.util import ArrayList, List
from java.net import URL
from javax.swing import JScrollPane, JSplitPane, JTabbedPane, JTable, SwingUtilities, JPanel, JButton, JLabel, JMenuItem, BoxLayout, Box, JTextField
from javax.swing.table import AbstractTableModel
from threading import Lock
import datetime, os, hashlib
import sys


'''
Entry point for Burp Git Bridge extension.
'''

class BurpExtender(IBurpExtender):
    '''
    Entry point for plugin; creates UI and Log
    '''
    
    def	registerExtenderCallbacks(self, callbacks):
        
        # Assign stdout/stderr for debugging and set extension name

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        callbacks.setExtensionName("Git Bridge")
        
        # import time
        # print(dir(callbacks))
        # print(callbacks.loadConfigFromJson())
        # for fn in dir(callbacks):
        #     if fn not in ['unloadExtension'] and not 'out' in fn:
        #         try:
        #             # print(fn, getattr(callbacks, fn)())
        #             print(fn, getattr(callbacks, fn))
        #             time.sleep(2)
        #         except:
        #             pass


        # Create major objects and load user data 

        self.log = Log(callbacks)
        self.ui = BurpUi(callbacks, self.log)
        self.log.setUi(self.ui)
        self.log.reload()
       
       

'''
Classes that support logging of data to in-Burp extension UI as well
as the underlying git repo
'''

class LogEntry(object):
    '''
    Hacky dictionary used to store Burp tool data. Objects of this class 
    are stored in the Java-style table represented in the Burp UI table.
    They are created by the BurpUi when a user sends Burp tool data to Git 
    Bridge, or by Git Bridge when a user's git repo is reloaded into Burp.
    '''
    def __init__(self, *args, **kwargs):
        self.__dict__ = kwargs


        # Hash most of the tool data to uniquely identify this entry.
        # Note: Could be more pythonic.

        md5 = hashlib.md5()
        for k, v in self.__dict__.iteritems():
            if v and k != "messages": 
                if not getattr(v, "__getitem__", False):
                    v = str(v)
                md5.update(k)
                md5.update(v[:2048])
        self.md5 = md5.hexdigest()



class Log():
    '''
    Log of burp activity: this class encapsulates both the Burp UI log and the git 
    repo log. A single object of this class is created when the extension is 
    loaded. It is used by BurpExtender when it logs input events or the 
    in-Burp Git Bridge log is reloaded from the underlying git repo.
    '''

    def __init__(self, callbacks):
        '''
        Creates GUI log and git log objects
        '''

        self.ui = None
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.gui_log = GuiLog(callbacks)
        self.git_log = GitLog(callbacks)

    def setUi(self, ui):
        '''
        There is a circular dependency between the Log and Burp GUI objects: 
        the GUI needs a handle to the Log to add new Burp tool data, and the 
        Log needs a handle to the GUI to update in the in-GUI table.

        The GUI takes the Log in its constructor, and this function gives the 
        Log a handle to the GUI.
        '''

        self.ui = ui
        self.gui_log.ui = ui

    def reload(self):
        '''
        Reloads the Log from on the on-disk git repo.
        '''
        self.gui_log.clear() 
        for entry in self.git_log.entries():
            self.gui_log.add_entry(entry)

    def add_repeater_entry(self, messageInfo):
        '''
        Loads salient info from the Burp-supplied messageInfo object and 
        stores it to the GUI and Git logs
        '''

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        service = messageInfo.getHttpService() 
        entry = LogEntry(tool="repeater",
                host=service.getHost(), 
                port=service.getPort(), 
                protocol=service.getProtocol(), 
                url=str(self._helpers.analyzeRequest(messageInfo).getUrl()), 
                timestamp=timestamp,
                who=self.git_log.whoami(),
                description='',
                request=messageInfo.getRequest(),
                response=messageInfo.getResponse())
        self.gui_log.add_entry(entry)
        self.git_log.add_repeater_entry(entry)

    def add_scanner_entry(self, scanIssue):
        '''
        Loads salient info from the Burp-supplied scanInfo object and 
        stores it to the GUI and Git logs
        '''

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Gather info from messages. Oi, ugly.

        messages = []
        for message in scanIssue.getHttpMessages():
            service = message.getHttpService() 
            msg_entry = LogEntry(tool="scanner_message",
                    host=service.getHost(), 
                    port=service.getPort(), 
                    protocol=service.getProtocol(), 
                    comment=message.getComment(),
                    highlight=message.getHighlight(),
                    request=message.getRequest(),
                    response=message.getResponse(),
                    timestamp=timestamp)
            messages.append(msg_entry)


        # Gather info for scan issue

        service = scanIssue.getHttpService() 
        entry = LogEntry(tool="scanner",
                timestamp=timestamp,
                who=self.git_log.whoami(),
                description='',
                messages=messages,
                host=service.getHost(), 
                port=service.getPort(), 
                protocol=service.getProtocol(), 
                confidence=scanIssue.getConfidence(),
                issue_background=scanIssue.getIssueBackground(),
                issue_detail=scanIssue.getIssueDetail(),
                issue_name=scanIssue.getIssueName(),
                issue_type=scanIssue.getIssueType(),
                remediation_background=scanIssue.getRemediationBackground(),
                remediation_detail=scanIssue.getRemediationDetail(),
                severity=scanIssue.getSeverity(),
                url=str(scanIssue.getUrl()))

        self.gui_log.add_entry(entry)
        self.git_log.add_scanner_entry(entry)

    def remove(self, entry):
        '''
        Removes the supplied entry from the Log
        '''

        self.git_log.remove(entry)
        self.gui_log.remove_entry(entry) 

    def pull(self):
        '''
        pulls the supplied entry from the Log
        '''
        self.git_log.pull()

    def push(self):
        '''
        Pushs the supplied entry from the Log
        '''
        self.git_log.push()

    def set_config(self, user, mail, repo):
        '''
        Set the supplied data to git config
        '''
        self.gui_log.clear()
        self.git_log.set_config(user, mail, repo)

    def delete_repo_local(self, repo):
        '''
        Set the supplied data to git config
        '''
        self.gui_log.clear()
        self.git_log.delete_repo_local(repo)

    def set_description(self, entry_hash, description):
        '''
        Set the supplied data to git config
        '''
        self.git_log.set_description(entry_hash, description)

    def get_actual_repo_uri(self):
        '''
        Get actual repo uri
        '''
        return self.git_log.get_actual_repo_uri()

    def reload_project(self):
        '''
        Reload config of burp project
        '''
        self.gui_log.clear()
        self.git_log.reload_project()

class GuiLog(AbstractTableModel):
    '''
    Acts as an AbstractTableModel for the table that is shown in the UI tab: 
    when this data structure changes, the in-UI table is updated.
    '''

    def __init__(self, callbacks):
        '''
        Creates a Java-style ArrayList to hold LogEntries that appear in the table
        '''

        self.ui = None
        self._log = ArrayList()
        self._lock = Lock()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.cols = ["Time added", 
                "Tool",
                "URL",
                "Issue",
                "Who",
                "Description"]

    def clear(self):
        '''
        Clears all entries from the table
        '''

        self._lock.acquire()
        last = self._log.size()
        if last > 0:
            self._log.clear()
            self.fireTableRowsDeleted(0, last-1)
        # Note: if callees modify table this could deadlock
        self._lock.release()

    def add_entry(self, entry):
        '''
        Adds entry to the table
        '''

        self._lock.acquire()
        row = self._log.size()
        self._log.add(entry)
        # Note: if callees modify table this could deadlock
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    def remove_entry(self, entry):
        '''
        Removes entry from the table
        '''

        self._lock.acquire()
        for i in range(0, len(self._log)):
            ei = self._log[i] 
            if ei.md5 == entry.md5:
                self._log.remove(i)
                break
        self.fireTableRowsDeleted(i, i) 
        self._lock.release()

    def getRowCount(self):
        '''
        Used by the Java Swing UI 
        '''

        try:
            return self._log.size()
        except:
            return 0
    
    def getColumnCount(self):
        '''
        Used by the Java Swing UI 
        '''

        return len(self.cols)
    
    def getColumnName(self, columnIndex):
        '''
        Used by the Java Swing UI 
        '''

        try:
            return self.cols[columnIndex]
        except KeyError:
            return ""

    def get(self, rowIndex):
        '''
        Gets the LogEntry at rowIndex
        '''
        return self._log.get(rowIndex)
    
    def getValueAt(self, rowIndex, columnIndex):
        '''
        Used by the Java Swing UI 
        '''

        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry.timestamp
        elif columnIndex == 1:
            return logEntry.tool.capitalize()
        elif columnIndex == 2:
            return logEntry.url
        elif columnIndex == 3:
            if logEntry.tool == "scanner":
                return logEntry.issue_name
            else:
                return "N/A"
        elif columnIndex == 4:
            return logEntry.who
        elif columnIndex == 5:
            return logEntry.description

        return ""

import os, subprocess
class GitLog(object):
    '''
    Represents the underlying Git Repo that stores user information. Used 
    by the Log object. As it stands, uses only a single git repo at a fixed 
    path.
    '''

    def __init__(self, callbacks):
        '''
        Initializes git repo config
        '''

        self.callbacks = callbacks
        self.repo_path = None

        self.home = os.path.expanduser("~")
        self.base_path = os.path.join(self.home, ".burp-git-bridge/")
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

        self.burp_config_path = os.path.join(self.home, ".java/.userPrefs/burp/prefs.xml")
        self.project_repo_path = os.path.join(self.base_path, "repo_path_relations.txt")
        # if not os.path.exists(self.repo_path):
        #     self._run_subprocess_command(["git", "init", self.repo_path], cwd=home)
        self.reload_project()

    def reload_project(self):
        # Load project-repo relations
        self.project_repo_rels = {}
        if os.path.exists(self.project_repo_path):
            with open(self.project_repo_path, "r") as f:
                for line in f.read().split('\n'):
                    try:
                        proj_name, repo = line.split(',')
                        self.project_repo_rels[proj_name] = repo
                    except Exception as e:
                        print("Cannot be unpacked file project_repo_path in line {}".format(line))

        # Load actual project name. If it is temporary project loads lastone. can it be hacked better?
        self.project_name = self.get_current_project_name()
        self.project_path = None
        if self.project_name == 'Temporary Project':
            self.project_name = None
            self.project_path = None
        else:
            try:
                # TODO: This can be better, right?
                with open(self.burp_config_path, "r") as f:
                    config = f.read().split('\n')
                    for line in config:
                        if 'suite.recentProjectNames' in line and self.project_name in line:
                            temp_project_id = line.split('suite.recentProjectNames')[1].split('" value="')[0]
                            search = 'suite.recentProjectNames'+temp_project_id
                            for line in config:
                                if search in line:
                                    self.project_path = line.split('value="')[1].split('"/>')[0]
            except:
                self.project_name = None
                self.project_path = None
        # try:
        #     # TODO: This can be better, right?
        #     with open(self.burp_config_path, "r") as f:
        #         config = f.read().split('\n')
        #         for line in config:
        #             if 'suite.recentProjectFiles0' in line:
        #                 self.project_path = line.split('value="')[1].split('"/>')[0]
        #             if 'suite.recentProjectNames0' in line:
        #                 self.project_name = line.split('value="')[1].split('"/>')[0]
        # except:
        #     self.project_name = None
        #     self.project_path = None
        
        if self.project_name in self.project_repo_rels.keys():
            self.repo_uri = self.project_repo_rels[self.project_name]
            self.repo_path = self._generate_path_repo_name(self._extract_repo_name(self.repo_uri))
        else:
            self.repo_uri = None
        
        print("Loaded project {}\nProject path {}\nRepo uri {}".format(self.project_name, self.project_path, self.repo_uri))

    def save_current_project_repo(self):
        print("saving project_repo_rels file project {} with repo {}".format(self.project_name, self.repo_uri))
        self.project_repo_rels[self.project_name] = self.repo_uri
        lines = '\n'.join(['{},{}'.format(k,v) for k, v in self.project_repo_rels.items()])
        with open(self.project_repo_path, "w") as f:
            f.write(lines)

    def _run_subprocess_command(self, cmd_list, cwd=None, quiet=False):
        process = subprocess.Popen(cmd_list, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        print("Subprocess: {}".format(cmd_list))
        if not quiet:
            print(out)
            print(err)
        if process.returncode != 0:
            if not quiet:
                print("########### Error on call: {}".format(cmd_list))
                print(out)
                print(err)
                print("########### End Error on call")
            raise Exception("Error on call: {}".format(cmd_list))
        return out
    
    def get_current_project_name(self):
        """
        Extracts project name from window, uglyy right?
        """
        w = None
        wids = self._run_subprocess_command(['xdotool', 'search', 'Burp'], quiet=True).decode()
        for wid in wids.split('\n'):
            try:
                wname = self._run_subprocess_command(['xdotool', 'getwindowname', wid], quiet=True).decode()
                if wname.startswith("Burp Suite Professional v"):
                    w = wname
            except:
                pass
        print(w)
        if w:
            return w.split(' - ')[1]

    def _generate_path_repo_name(self, repo_name):
        return os.path.join(self.base_path, repo_name)

    def _extract_repo_name(self, repo_uri):
        return repo_uri.split('/')[-1].split('.git')[0]

    def add_repeater_entry(self, entry):
        '''
        Adds a LogEntry containing Burp Repeater data to the git repo
        '''

        # Make directory for this entry

        entry_dir = os.path.join(self.repo_path, entry.md5)
        if not os.path.exists(entry_dir):
            os.mkdir(entry_dir)
        
        # Add and commit repeater data to git repo

        self.write_entry(entry, entry_dir)
        self._run_subprocess_command(["git", "commit", "-m", "Added Repeater entry"], 
                cwd=self.repo_path)

    def add_scanner_entry(self, entry):
        '''
        Adds a LogEntry containing Burp Scanner data to the git repo
        '''

        # Create dir hierarchy for this issue

        entry_dir = os.path.join(self.repo_path, entry.md5)


        # Log this entry; log 'messages' to its own subdir 

        messages = entry.messages
        del entry.__dict__["messages"]
        self.write_entry(entry, entry_dir)
        messages_dir = os.path.join(entry_dir, "messages")
        if not os.path.exists(messages_dir):
            os.mkdir(messages_dir)
            lpath = os.path.join(messages_dir, ".burp-list")
            open(lpath, "wt")
            self._run_subprocess_command(["git", "add", lpath], cwd=self.repo_path)
        i = 0
        for message in messages:
            message_dir = os.path.join(messages_dir, str(i))
            if not os.path.exists(message_dir):
                os.mkdir(message_dir)
            self.write_entry(message, message_dir)
            i += 1

        self._run_subprocess_command(["git", "commit", "-m", "Added scanner entry"], 
                cwd=self.repo_path)


    def write_entry(self, entry, entry_dir):
        '''
        Stores a LogEntry to entry_dir and adds it to git repo.
        '''

        if not os.path.exists(entry_dir):
            os.mkdir(entry_dir)
        for filename, data in entry.__dict__.iteritems():
            if not data:
                data = ""
            if not getattr(data, "__getitem__", False):
                data = str(data)
            path = os.path.join(entry_dir, filename)
            with open(path, "wb") as fp:
                fp.write(data)
                fp.flush()
            self._run_subprocess_command(["git", "add", path], 
                    cwd=self.repo_path)


    def entries(self):
        '''
        Generator; yields a LogEntry for each entry in the on-disk git repo
        '''

        def load_entry(entry_path):
            '''
            Loads a single entry from the path. Could be a "list" entry (see
            below)
            '''

            entry = LogEntry()
            for filename in os.listdir(entry_path):
                file_path = os.path.join(entry_path, filename)
                if os.path.isdir(file_path):
                    if ".burp-list" in os.listdir(file_path):
                        list_entry = load_list(file_path)
                        entry.__dict__[filename] = list_entry
                    else:
                        sub_entry = load_entry(file_path)
                        entry.__dict__[filename] = sub_entry
                else:
                    entry.__dict__[filename] = open(file_path, "rb").read()
            return entry

        def load_list(entry_path):
            '''
            Loads a "list" entry (corresponds to a python list, or a Java 
            ArrayList, such as the "messages" member of a Burp Scanner Issue).
            '''

            entries = []
            for filename in os.listdir(entry_path):
                file_path = os.path.join(entry_path, filename)
                if filename == ".burp-list":
                    continue
                entries.append(load_entry(file_path))
            return entries


        # Process each of the directories in the underlying git repo 

        if self.repo_path:
            for entry_dir in os.listdir(self.repo_path):
                if entry_dir == ".git":
                    continue
                entry_path = os.path.join(self.repo_path, entry_dir)
                if not os.path.isdir(entry_path):
                    continue
                entry = load_entry(entry_path)
                yield entry


    def whoami(self):
        '''
        Returns user.name from the underlying git repo. Used to note who 
        created or modified an entry.
        '''

        return self._run_subprocess_command(["git", "config", "user.name"], 
                cwd=self.repo_path)

    def remove(self, entry):
        '''
        Removes the given LogEntry from the underlying git repo.
        '''
        entry_path = os.path.join(self.repo_path, entry.md5)
        self._run_subprocess_command(["git", "rm", "-rf", entry_path], 
           cwd=self.repo_path)
        self._run_subprocess_command(["git", "commit", "-m", "Removed entry at %s" % 
            entry_path], cwd=self.repo_path)

    def pull(self):
        '''
        pulles the actual state from the underlying git repo.
        '''
        self._run_subprocess_command(["git", "pull"], cwd=self.repo_path)

    def push(self):
        '''
        Pushes the actual state from the underlying git repo.
        '''
        print(self._run_subprocess_command(["git", "pull"], cwd=self.repo_path))
        print(self._run_subprocess_command(["git", "push", "origin", "master"], cwd=self.repo_path))

    def set_config(self, user, email, repo_uri):
        '''
        Set the supplied data to git config
        '''
        self.repo_name = self._extract_repo_name(repo_uri)
        self.repo_path = self._generate_path_repo_name(self.repo_name)
        self.repo_uri = repo_uri
        self.user = user
        self.email = email

        server = repo_uri.split('@')[1].split(':')[0]
        keys = self._run_subprocess_command(["ssh-keyscan", server]).decode()
        hosts_file = os.path.join(self.home, ".ssh/known_hosts")

        with open(hosts_file, "r") as f:
            lines = f.read().split('\n')
        
        for k in keys.split('\n'):
            if not k in lines:
                lines.append(k)

        with open(hosts_file, "w") as f:
            f.write('\n'.join(lines))

        self._run_subprocess_command(["git", "config", "--global", "user.name", user], cwd=self.base_path)
        self._run_subprocess_command(["git", "config", "--global", "user.email", email], cwd=self.base_path)
        
        if not os.path.exists(self.repo_path):
            self._run_subprocess_command(["git", "clone", repo_uri, self.repo_name], cwd=self.base_path)
        
        self.save_current_project_repo()

    def delete_repo_local(self, repo_uri):
        '''
        Deletes local repo_uri folder.
        '''
        repo_name = self._extract_repo_name(repo_uri)
        self._run_subprocess_command(["rm", "-rf", repo_name], cwd=self.base_path)

    def set_description(self, entry_hash, description):
        '''
        Set description data in local repo folder, commit and push.
        '''
        entry_path = os.path.join(self.repo_path, entry_hash)
        who_file = os.path.join(entry_path, 'who')
        description_file = os.path.join(entry_path, 'description')
        
        with open(who_file, "r") as f:
            who = f.read()
        
        if who != self.whoami():
            print("You cannot edit description entry that you not created (check 'who' field)")
            return False

        with open(description_file, 'w') as f:
            f.write(description)
                
        self._run_subprocess_command(["git", "add", description_file], 
                cwd=self.repo_path)
        self._run_subprocess_command(["git", "commit", "-m", "Edited description entry"], 
                        cwd=self.repo_path)
        self.push()

    def get_actual_repo_uri(self):
        return self.repo_uri


'''
Implementation of extension's UI.
'''

class BurpUi(ITab):
    '''
    The collection of objects that make up this extension's Burp UI. Created
    by BurpExtender.
    '''

    def __init__(self, callbacks, log):
        '''
        Creates GUI objects, registers right-click handlers, and adds the 
        extension's tab to the Burp UI.
        '''

        # Create split pane with top and bottom panes

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.bottom_pane = UiBottomPane(callbacks, log)
        self.top_pane = UiTopPane(callbacks, self.bottom_pane, log)
        self.bottom_pane.setLogTable(self.top_pane.logTable)
        self._splitpane.setLeftComponent(self.top_pane)
        self._splitpane.setRightComponent(self.bottom_pane)


        # Create right-click handler

        self.log = log
        rc_handler = RightClickHandler(callbacks, log)
        callbacks.registerContextMenuFactory(rc_handler)

        
        # Add the plugin's custom tab to Burp's UI

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.addSuiteTab(self)

      
    def getTabCaption(self):
        return "Git"
       
    def getUiComponent(self):
        return self._splitpane

class RightClickHandler(IContextMenuFactory):
    '''
    Creates menu items for Burp UI right-click menus.
    '''

    def __init__(self, callbacks, log):
        self.callbacks = callbacks
        self.log = log

    def createMenuItems(self, invocation):
        '''
        Invoked by Burp when a right-click menu is created; adds Git Bridge's 
        options to the menu.
        '''

        context = invocation.getInvocationContext()
        tool = invocation.getToolFlag()
        if tool == self.callbacks.TOOL_REPEATER:
            if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                item = JMenuItem("Send to Git Bridge")
                item.addActionListener(self.RepeaterHandler(self.callbacks, invocation, self.log))
                items = ArrayList()
                items.add(item)
                return items
        elif tool == self.callbacks.TOOL_SCANNER:
            if context in [invocation.CONTEXT_SCANNER_RESULTS]:
                item = JMenuItem("Send to Git Bridge")
                item.addActionListener(self.ScannerHandler(self.callbacks, invocation, self.log))
                items = ArrayList()
                items.add(item)
                return items
        else:
            # TODO: add support for other tools
            pass

    class ScannerHandler(ActionListener):
        '''
        Handles selection of the 'Send to Git Bridge' menu item when shown 
        on a Scanner right click menu.
        '''

        def __init__(self, callbacks, invocation, log):
            self.callbacks = callbacks
            self.invocation = invocation
            self.log = log

        def actionPerformed(self, actionEvent):
            for issue in self.invocation.getSelectedIssues():
                self.log.add_scanner_entry(issue) 

    class RepeaterHandler(ActionListener):
        '''
        Handles selection of the 'Send to Git Bridge' menu item when shown 
        on a Repeater right click menu.
        '''

        def __init__(self, callbacks, invocation, log):
            self.callbacks = callbacks
            self.invocation = invocation
            self.log = log

        def actionPerformed(self, actionEvent):
            for message in self.invocation.getSelectedMessages():
                self.log.add_repeater_entry(message) 

class UiBottomPane(JTabbedPane, IMessageEditorController):
    '''
    The bottom pane in the this extension's UI tab. It shows detail of 
    whatever is selected in the top pane.
    '''

    def __init__(self, callbacks, log):
        self.configPanel = ConfigPanel(callbacks, log)
        self.addTab("Git Config", self.configPanel)
        self.commandPanel = CommandPanel(callbacks, log)
        self.addTab("Git Commands", self.commandPanel)
        self.editPanel = EntryEditPanel(callbacks, log)
        # self.addTab("Entry edit", self.editPanel)
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._issueViewer = callbacks.createMessageEditor(self, False)
        callbacks.customizeUiComponent(self)

    def setLogTable(self, log_table):
        '''
        Passes the Log table to the "Send to Tools" component so it can grab
        the selected rows
        '''
        self.commandPanel.log_table = log_table
        self.editPanel.log_table = log_table
        self.configPanel.log_table = log_table

    def show_log_entry(self, log_entry):
        '''
        Shows the log entry in the bottom pane of the UI
        '''

        self.removeAll()
        self.addTab("Git Config", self.configPanel)
        self.addTab("Git Commands", self.commandPanel)
        self.addTab("Entry Edit", self.editPanel)
        if getattr(log_entry, "request", False):
            self.addTab("Request", self._requestViewer.getComponent())
            self._requestViewer.setMessage(log_entry.request, True)
        if getattr(log_entry, "response", False):
            self.addTab("Response", self._responseViewer.getComponent())
            self._responseViewer.setMessage(log_entry.response, False)
        if log_entry.tool == "scanner":
            self.addTab("Issue Summary", self._issueViewer.getComponent())
            self._issueViewer.setMessage(self.getScanIssueSummary(log_entry), 
                    False)
        self._currentlyDisplayedItem = log_entry

    def getScanIssueSummary(self, log_entry):
        '''
        A quick hack to generate a plaintext summary of a Scanner issue. 
        This is shown in the bottom pane of the Git Bridge tab when a Scanner 
        item is selected.
        '''

        out = []
        for key, val in sorted(log_entry.__dict__.items()):
            if key in ["messages", "tool", "md5"]:
                continue
            out.append("%s: %s" % (key, val))
        return "\n\n".join(out)
        
    '''
    The three methods below implement IMessageEditorController st. requests 
    and responses are shown in the UI pane
    '''

    def getHttpService(self):
        return self._currentlyDisplayedItem.requestResponse.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.requestResponse.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

 
class UiTopPane(JTabbedPane):
    '''
    The top pane in this extension's UI tab. It shows the in-Burp version of 
    the Git Repo.
    '''

    def __init__(self, callbacks, bottom_pane, log):
        self.logTable = UiLogTable(callbacks, bottom_pane, log.gui_log)
        scrollPane = JScrollPane(self.logTable)
        self.addTab("Repo", scrollPane)
        callbacks.customizeUiComponent(self)

class UiLogTable(JTable):
    '''
    Table of log entries that are shown in the top pane of the UI when
    the corresponding tab is selected.
    
    Note, as a JTable, this stays synchronized with the underlying
    ArrayList. 
    '''

    def __init__(self, callbacks, bottom_pane, gui_log):
        self.setAutoCreateRowSorter(True)
        self.bottom_pane = bottom_pane
        self._callbacks = callbacks
        self.gui_log = gui_log
        self.setModel(gui_log)
        callbacks.customizeUiComponent(self)

    def getSelectedEntries(self):
        return [self.gui_log.get(i) for i in self.getSelectedRows()]
    
    def changeSelection(self, row, col, toggle, extend):
        '''
        Displays the selected item in the content pane
        '''
    
        JTable.changeSelection(self, row, col, toggle, extend)
        self.bottom_pane.show_log_entry(self.gui_log.get(row))

class EntryEditPanel(JPanel, ActionListener):
    '''
    This is the "Entry Edit" Panel shown in the bottom of the Git
    Bridge tab.
    '''

    def __init__(self, callbacks, log):
        self.callbacks = callbacks
        self.log = log
        self.log_table = None # to be set by caller

        self.setLayout(BoxLayout(self, BoxLayout.PAGE_AXIS))

        boxHorizontal = Box.createHorizontalBox()
        button = JButton("Set new description")
        boxHorizontal.add(JLabel("Set new description to selected items. Only edits if you are who created them."))
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        button = JButton("Set new description")
        self.description_box = JTextField('', 10)
        self.description_box.setText('')
        button.addActionListener(EntryEditPanel.SetDescriptionAction(self, log, self.description_box))
        boxHorizontal.add(JLabel("  New description: "))
        boxHorizontal.add(self.description_box)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

    class SetDescriptionAction(ActionListener):
        '''
        Iterates over each entry that is selected in the UI table and 
        set description to and from the Log. 
        '''

        def __init__(self, panel, log, description_box):
            self.panel = panel
            self.log = log
            self.description_box = description_box
    
        def actionPerformed(self, event):
            '''
            Iterates over each entry that is selected in the UI table and 
            removes it from the Log. 
            '''
            entries = self.panel.log_table.getSelectedEntries()
            for entry in entries:
                self.log.set_description(entry.md5, self.description_box.getText())
            
            self.log.reload()



class ConfigPanel(JPanel, ActionListener):
    '''
    This is the "Git Bridge Commands" Panel shown in the bottom of the Git
    Bridge tab.
    '''

    def __init__(self, callbacks, log):
        self.callbacks = callbacks
        self.log = log
        self.log_table = None # to be set by caller
        # self.log.reload()
        self.repo = self.log.get_actual_repo_uri()
        try:
            self.email = callbacks.loadExtensionSetting("git_email")
        except:
            self.email = ""
        try:
            self.name = callbacks.loadExtensionSetting("git_name")
        except:
            self.name = ""

        self.setLayout(BoxLayout(self, BoxLayout.PAGE_AXIS))

        to_disable = []

        boxHorizontal = Box.createHorizontalBox()
        self.user_box = JTextField('', 10)
        self.user_box.setText(self.name)
        boxHorizontal.add(JLabel("  user.name: "))
        boxHorizontal.add(self.user_box)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        self.email_box = JTextField('', 10)
        self.email_box.setText(self.email)
        boxHorizontal.add(JLabel("  user.email: "))
        boxHorizontal.add(self.email_box)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        self.repo_box = JTextField('', 10)
        self.repo_box.setText(self.repo)
        boxHorizontal.add(JLabel("  Git Repo: "))
        boxHorizontal.add(self.repo_box)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        button = JButton("Set and Reload")
        button.addActionListener(ConfigPanel.SetConfigAction(log, callbacks, self.user_box, self.email_box, self.repo_box))
        boxHorizontal.add(JLabel("Set, save and reload values:"))
        boxHorizontal.add(button)
        self.add(boxHorizontal)
        to_disable.append(button)

        boxHorizontal = Box.createHorizontalBox()
        button = JButton("Delete")
        button.addActionListener(ConfigPanel.DeleteAction(log, self.repo_box))
        boxHorizontal.add(JLabel("Delete repo locally to clone again later (will lose all changes):"))
        boxHorizontal.add(button)
        self.add(boxHorizontal)
        to_disable.append(button)

        # to_disable.append(self.user_box)
        # to_disable.append(self.email_box)
        # to_disable.append(self.repo_box)
        # for item in to_disable:
        #     item.setVisible(False)
        # self.revalidate()
        # self.repaint()

        # boxHorizontal = Box.createHorizontalBox()
        # button = JButton("Reload Actual Project Config")
        # button.addActionListener(ConfigPanel.ReloadActualProjectAction(log, self.repo_box, to_disable, self))
        # boxHorizontal.add(JLabel("Because we cannot get actual project, maybe you want to reload:"))
        # boxHorizontal.add(button)
        # self.add(boxHorizontal)


    class SetConfigAction(ActionListener):
        '''
        Handles when the "SetConfig" button is clicked.
        '''

        def __init__(self, log, callbacks, userBox, emailBox, repoBox):
            self.log = log
            self.callbacks = callbacks
            self.user_box = userBox
            self.email_box = emailBox
            self.repo_box = repoBox
    
        def actionPerformed(self, event):
            self.repo = self.callbacks.saveExtensionSetting("git_repo", self.repo_box.getText())
            self.email = self.callbacks.saveExtensionSetting("git_email", self.email_box.getText())
            self.name = self.callbacks.saveExtensionSetting("git_name", self.user_box.getText())
            self.log.set_config(self.user_box.getText(), self.email_box.getText(), self.repo_box.getText())
            self.log.reload_project()

    class DeleteAction(ActionListener):
        '''
        Handles when the "Delete" button is clicked.
        '''

        def __init__(self, log, repoBox):
            self.log = log
            self.repo_box = repoBox
    
        def actionPerformed(self, event):
            self.log.delete_repo_local(self.repo_box.getText())


    class ReloadActualProjectAction(ActionListener):
        '''
        Handles when the "ReloadActualProject" button is clicked.
        '''

        def __init__(self, log, repo_box, to_disable, panel):
            self.log = log
            self.repo_box = repo_box
            self.to_disable = to_disable
            self.panel = panel
    
        def actionPerformed(self, event):
            self.log.reload_project()
            self.repo_box.setText(self.log.get_actual_repo_uri())
            for item in self.to_disable:
                item.setVisible(True)
            self.panel.revalidate()
            self.panel.repaint()


class CommandPanel(JPanel, ActionListener):
    '''
    This is the "Git Bridge Commands" Panel shown in the bottom of the Git
    Bridge tab.
    '''

    def __init__(self, callbacks, log):
        self.callbacks = callbacks
        self.log = log
        self.log_table = None # to be set by caller

        self.setLayout(BoxLayout(self, BoxLayout.PAGE_AXIS))

        boxHorizontal = Box.createHorizontalBox()
        label = JLabel("Reload from Git Repo:")
        button = JButton("Reload")
        button.addActionListener(CommandPanel.ReloadAction(log))
        boxHorizontal.add(label)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        label = JLabel("Send selected entries to respective Burp tools:")
        button = JButton("Send")
        button.addActionListener(CommandPanel.SendAction(self))
        boxHorizontal.add(label)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        label = JLabel("Remove selected entries from Git Repo:")
        button = JButton("Remove")
        button.addActionListener(CommandPanel.RemoveAction(self, log))
        boxHorizontal.add(label)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

        # TODO: maybe add a git command box
        

        boxHorizontal = Box.createHorizontalBox()
        label = JLabel("Pull to Git Repo:")
        button = JButton("Pull")
        button.addActionListener(CommandPanel.PullAction(log, callbacks))
        boxHorizontal.add(label)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        label = JLabel("Push to Git Repo:")
        button = JButton("Push")
        button.addActionListener(CommandPanel.PushAction(log, callbacks))
        boxHorizontal.add(label)
        boxHorizontal.add(button)
        self.add(boxHorizontal)

    class ReloadAction(ActionListener):
        '''
        Handles when the "Reload" button is clicked.
        '''

        def __init__(self, log):
            self.log = log
    
        def actionPerformed(self, event):
            self.log.reload()

    class SendAction(ActionListener):
        '''
        Handles when the "Send to Tools" button is clicked.
        '''

        def __init__(self, panel):
            self.panel = panel

        def actionPerformed(self, actionEvent):
            '''
            Iterates over each entry that is selected in the UI table and 
            calls the proper Burp "send to" callback with the entry data.
            '''

            for entry in self.panel.log_table.getSelectedEntries():
                if entry.tool == "repeater":
                    https = (entry.protocol == "https")
                    self.panel.callbacks.sendToRepeater(entry.host, 
                            int(entry.port), https, entry.request, 
                            entry.timestamp)
                elif entry.tool == "scanner":
                    issue = BurpLogScanIssue(entry)
                    self.panel.callbacks.addScanIssue(issue)

    class RemoveAction(ActionListener):
        '''
        Handles when the "Remove" button is clicked.
        '''

        def __init__(self, panel, log):
            self.panel = panel
            self.log = log

        def actionPerformed(self, event):
            '''
            Iterates over each entry that is selected in the UI table and 
            removes it from the Log. 
            '''
            entries = self.panel.log_table.getSelectedEntries()
            for entry in entries:
                self.log.remove(entry)

    class PullAction(ActionListener):
        '''
        Handles when the "Pull to repo" button is clicked.
        '''

        def __init__(self, log, callbacks):
            self.log = log
            self._callbacks = callbacks
    
        def actionPerformed(self, event):
            self.log.pull()
            self.log.reload()
            
    class PushAction(ActionListener):
        '''
        Handles when the "Push to repo" button is clicked.
        '''

        def __init__(self, log, callbacks):
            self.log = log
            self._callbacks = callbacks
    
        def actionPerformed(self, event):
            self.log.push()


'''
Burp Interoperability Class Definitions
'''

class BurpLogHttpService(IHttpService):
    '''
    Burp expects the object passed to "addScanIssue" to include a member 
    that implements this interface; that is what this object is used for.
    '''

    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return int(self._port)

    def getProtocol(self):
        return self._protocol

class BurpLogHttpRequestResponse(IHttpRequestResponse):
    '''
    Burp expects the object passed to "addScanIssue" to include a member 
    that implements this interface; that is what this object is used for.
    '''

    def __init__(self, entry):
        self.entry = entry

    def getRequest(self):
        return self.entry.request
    def getResponse(self):
        return self.entry.response
    def getHttpService(self):
        return BurpLogHttpService(self.entry.host,
                self.entry.port, self.entry.protocol)


class BurpLogScanIssue(IScanIssue):
    '''
    Passed to addScanItem.

    Note that a pythonic solution that dynamically creates method based on 
    LogEntry attributes via functools.partial will not work here as the 
    interface classes supplied by Burp (IScanIssue, etc.) include read-only
    attributes corresponding to strings that would be used by such a solution.
    '''

    def __init__(self, entry):
        self.entry = entry
        self.messages = [BurpLogHttpRequestResponse(m) for m in self.entry.messages]
        self.service = BurpLogHttpService(self.entry.host, self.entry.port, self.entry.protocol)

    def getHttpMessages(self):
        return self.messages
    def getHttpService(self):
        return self.service

    def getConfidence(self):
        return self.entry.confidence
    def getIssueBackground(self):
        return self.entry.issue_background
    def getIssueDetail(self):
        return self.entry.issue_detail
    def getIssueName(self):
        return self.entry.issue_name
    def getIssueType(self):
        return self.entry.issue_type
    def getRemediationDetail(self):
        return self.entry.remediation_detail
    def getSeverity(self):
        return self.entry.severity
    def getUrl(self):
        return URL(self.entry.url)
