from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'HostEnum',

            'Author': ['@andrewchiles'],

            'Description': ('Performs detailed enumeration of the local system in the current user content.' 
                            'Optionaly performs Privesc checks and basic Windows Domain enumeration.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language': 'powershell',

            'MinLanguageVersion': '2',
            
            'Comments': [
                'https://github.com/threatexpress/red-team-scripts'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Local' : {
                'Description'   :   'Perform local Windows enumeration functions.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'Perform additional Windows Domain enumeration functions.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Privesc' : {
                'Description'   :   'Perform additional privilege escalation checks (PowerUp).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Quick' : {
                'Description'   :   'Perform a quick system survey.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTMLReport' : {
                'Description'   :   'Create an HTML formatted report in current directory.'
                                    'Output filename convention is YYYYMMDD_HHMMSS_HOSTNAME.html',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/host/HostEnum.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        script += "Invoke-HostEnum "

        # add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])

        return script
