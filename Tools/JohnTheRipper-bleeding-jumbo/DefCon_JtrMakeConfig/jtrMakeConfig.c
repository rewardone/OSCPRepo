/////////////////////////////////////////////////////////////////////
//Note, this code was originally written by Matt Weir, at Florida State University
//Contact Info weir -at- cs.fsu.edu
//This code is licensed GPLv2
//If you make any changes I would love to hear about them so I don't have to impliment them myself ;)

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAXUSERINPUT 14


///////////////////////////////////////////////////////////////////////////////////////////////
//This structure holds one mangling rule
//Note, multiple mangling rules can be combined per JtR main rule
//Aka the first structure could hold, (lowercase all letters)
//The second structure, (pointed to by next), could hold (Add two numbers at the end)
//The third structure could hold (Add one number at the begining)
//The "next" value of the third structure would be NULL to signal the end
//So that rule would create the guess "1password11"
typedef struct ruleStruct {
  char desc[100];                //A description to show the user
  int addType;                   //Used when the user wants to choose the default list 0=none, 1=lowercase,2=uppercase,3=number,4=special
  char jtrRule[100];             //the actual JtR configured rule, note does not contain ranges from the default list, (see addType)
  ruleStruct *next;                //Points to the next rule to apply
}ruleType;


///////////////////////////////////////////////////////////////////////////////////////////////
//This structure holds all the currently selected JtR main rules
//value points to a individual rule
typedef struct listStruct {
  ruleType *value;
  listStruct *next;
  char comment[100];             //A user defined comment
}listType;



typedef struct choiceStruct {
  int maxSize;                  //maximum size of a password, set to 0 for no maximum size
  int minSize;                  //minimum size of a password, set to 0 for no minimum size
  int numberAllowed;            //boolean, are numbers allowed?
  int specialAllowed;           //boolean, are special characters allowed?
  int lowerAllowed;             //boolean, are lower case characters allowed?
  int upperAllowed;             //boolean, are upper case characters allowed
  char lowerSet[100];               //list of allowed apha characters, allow the ability to modify for markov and forign languages
  char upperSet[100];               //list of allowed uppercase characters
  char specialSet[100];             //list of allowed special characters
  char numberSet[100];              //list of allowed numbers
  int minNumber;                //number of required numbers
  int minUpper;                 //number of required uppercase letters
  int minSpecial;               //number of requires special characters
  int minLower;                 //number of required lowercase letters 
  listType *userRules;           //The user specified JtR rules
} choiceType;



int initilize(choiceType *userChoice);
int getInfo(choiceType *userChoice);
int writeConfig(choiceType *userChoice);
int displaySplash();
int displayMain();
int getChoice(int maxChoice);
int modifyCharacterValue(choiceType* userChoice);
int displayModifyCharacterValue(choiceType* userChoice);
int modifyChar(char *inputString);
int passRules(choiceType* userChoice);
int displayPassRules(choiceType* userChoice);
int getInputValue(int maxChoice);
int passMangle(choiceType* userChoice);
int displayPassMangle();
int displayRules(choiceType* userChoice);
int manuallyAddRule(choiceType* userChoice);
int deleteRule(choiceType* userChoice);
int moveRule(choiceType* userChoice);
int saveConfig(choiceType* userChoice);
int loadConfig(choiceType* userChoice);
int getLoadNumber(FILE *loadFile);
int createJtr(choiceType* userChoice);
int displayMainGuide(listType *tempList);
int ruleGuidedMain(choiceType* userChoice);
int ruleHelp();
int insertMangleRule(ruleType *tempRule);
int caseMangleRule(ruleType *tempRule);
char getJtrPos(int size);
int addCommentRule(listType *tempList); 
int assortedMangleRule(ruleType *tempRule);
int replaceMangleRule(ruleType *tempRule);
int deleteMangleRule(ruleType *tempRule);

int main(int argc, char *argv[]) {
  choiceType userChoice;
 
  if (initilize(&userChoice)) {
    return -1;
  }
  if (getInfo(&userChoice)) {
    return -1;
  }
  return 0;
}
 
int initilize(choiceType *userChoice) {
  ruleType *tempValue;

  userChoice->maxSize=0;
  userChoice->minSize=0;
  userChoice->numberAllowed=1;
  userChoice->specialAllowed=1;
  userChoice->lowerAllowed=1;
  userChoice->upperAllowed=1;
  strncpy(userChoice->lowerSet,"abcdefghijklmnopqrstuvwxyz",26);
  strncpy(userChoice->numberSet,"0123456789",10);
  strncpy(userChoice->upperSet,"ABCDEFGHIJKLMNOPQRSTUVWXYZ",26);
  strncpy(userChoice->specialSet,"!@#$%^&*()_+\\-=?.,/\\\\\":; ",99);
  userChoice->minNumber=0;
  userChoice->minUpper=0;
  userChoice->minSpecial=0;
  userChoice->minLower=0;

  //---------Add the default rule, ":" which is to try the regular word without any mangling--//
  userChoice->userRules= new listType;
  userChoice->userRules->next=NULL;
  userChoice->userRules->comment[0]='\0';
  tempValue = new ruleType;
  tempValue->addType=0;
  strncpy(tempValue->jtrRule,":",2);
  strncpy(tempValue->desc,"no-op: Do nothing to the input word",99);
  tempValue->next=NULL;
  userChoice->userRules->value=tempValue;  
  return 0;
}

int getInfo(choiceType *userChoice) {
  int choice;
  int quitValue; //the menu option to quit
  int result;

  quitValue=7;
  displaySplash();
  choice=displayMain();
  while (choice!=quitValue) { //while the use hasn't selected quit
    if (choice==1) { //Yes, I don't like switch statements, so sue me.  Modify Character Values  
      result=modifyCharacterValue(userChoice);      
    }
    else if (choice==2) {
      result=passRules(userChoice); 
    }
    else if (choice==3) {
      result=passMangle(userChoice); 
    }
    else if (choice==4) {
      result=createJtr(userChoice);
    }
    else if (choice==5) {
      result=saveConfig(userChoice); 
    }
    else if (choice==6) {
      result=loadConfig(userChoice);
    } 
    choice=displayMain();
  }
  return 0;
}

int writeConfig(choiceType *userChoice) {

  return 0;
}

int displaySplash() {
  printf("****************************************************************\n");
  printf("*           John the Ripper Config File Generator              *\n");
  printf("*      (at least until I can come up with a better name)       *\n");
  printf("*                                                              *\n");
  printf("*                    Version 1.0.1                             *\n");
  printf("* Author: Matt Weir                                            *\n");
  printf("* Contact Info: weir [at] cs [dot] fsu [dot] edu               *\n");
  printf("* Special thanks to Florida State University and the National  *\n");
  printf("* Institute of Justice for funding this research               *\n");
  printf("****************************************************************\n\n\n");
  return 0;
}

int displayMain() {
  int choice;
  int result;
  printf("Please select an option\n");
  printf("(1) Modify the character sets,   (aka special characters =[!@#$%^&*])\n");
  printf("(2) Set password creation rules, (aka must contain at least one number, or must be at least 8 characters long)\n");
  printf("(3) Set word mangling rules,     (aka add two numbers to the end)\n");
  printf("(4) Create JtR config file\n");
  printf("(5) Save settings\n");
  printf("(6) Load settings\n");
  printf("(7) Quit\n");
  
  choice=getChoice(7);
  return choice;
}


int getChoice(int maxChoice) {
  int choice;
  char userInput[MAXUSERINPUT];
  choice = 0;
  printf("\nPlease choose one of the options\n");
  printf("<enter choice>:");
  while (choice==0) {
    fgets(userInput,MAXUSERINPUT-1,stdin);
    if (userInput!=NULL) {
      choice = atoi(userInput);
      if (choice > maxChoice) {
        choice=0;
      }
      else if (choice<0) {
        choice=0;
      }
      if (choice==0) {
        printf("Please choose one of the options\n");
        printf("<enter choice>:");
      }
    }
    rewind(stdin);
  }
  return choice;
}

int modifyCharacterValue(choiceType* userChoice) {
  int choice;
  int result;
  choice=displayModifyCharacterValue(userChoice); 
  while (choice!=5) {
    if (choice==1) {
      modifyChar(userChoice->lowerSet);
    }
    else if (choice==2) {
      modifyChar(userChoice->upperSet);
    }
    else if (choice==3) {
      modifyChar(userChoice->numberSet);
    }
    else if (choice==4) {
      modifyChar(userChoice->specialSet);
    }
    choice=displayModifyCharacterValue(userChoice);
  }
  return 0;
}

int displayModifyCharacterValue(choiceType* userChoice) {
  int choice;
  int result;
  printf("\nPlease select an option\n");
  printf("(1) Modify the lowercase character set.  Current set=(%s)\n",userChoice->lowerSet);
  printf("(2) Modify the UPPERCASE character set.  Current set=(%s)\n",userChoice->upperSet);
  printf("(3) Modify the number character set.     Current set=(%s)\n",userChoice->numberSet);
  printf("(4) Modify the special character set.    Current set=(%s)\n",userChoice->specialSet);
  printf("(5) Go back to the previous menu\n");

  choice=getChoice(5);
  return choice;
}

int modifyChar(char *inputString) {
  char userInput[100];
  int size;
  int changed;
  int i;
  int j;
  printf("\nPlease type the new string you want to use.  Hit enter when you are done\n");
  printf("<New Character String:>");
  fgets(userInput,100-1,stdin);
  size=strlen(userInput);
  userInput[size-1]='\0';  //gets rid of the return char

  //-----------Check for any characters that need an escape character in front of them-------//
  changed=0;
  i=0;
  j=0;
  while (userInput[i]!='\0') {
    if ((userInput[i]=='[')||(userInput[i]==']')||(userInput[i]=='-')||(userInput[i]=='\\')) {
      changed=1;
      inputString[j]='\\';
      j++;
    }
    inputString[j]=userInput[i];
    i++;
    j++;
  }
  inputString[j]='\0';
  if (changed) {
    printf("\n*Note the escape character '\\' was added to your string since JtR requires it for one or more of the characters you entered\n");
  }

  return 0;
}

int passRules(choiceType *userChoice) {
  int choice;
  int result;
  choice=displayPassRules(userChoice);
  while (choice!=11) {
    if (choice==1) {
      printf("\nPlease enter in the minimum password size, (0 is allowed to make no minimum password size)\n");
      userChoice->minSize=getInputValue(0);
    }
    else if (choice==2) {
      printf("\nPlease enter the maximum password size, (Enter '0' to disable the maximum password length requirement)\n");
      userChoice->maxSize=getInputValue(0);
    }
    else if (choice==3) {
      printf("\nPlease enter the number of REQUIRED lowercase characters\n");
      userChoice->minLower=getInputValue(userChoice->maxSize);
      if (userChoice->minLower!=0) {
        userChoice->lowerAllowed=1;
      }
    }
    else if (choice==4) {
      printf("\nPlease enter the number of REQUIRED UPPERCASE characters\n");
      userChoice->minUpper=getInputValue(userChoice->maxSize);
      if (userChoice->minUpper!=0) {
        userChoice->upperAllowed=1;
      }
    }
    else if (choice==5) {
      printf("\nPlease enter the number of REQUIRED numbers\n");
      userChoice->minNumber=getInputValue(userChoice->maxSize);
      if (userChoice->minNumber!=0) {
        userChoice->numberAllowed=1;
      }
    }
    else if (choice==6) {
      printf("\nPlease enter the number of REQUIRED special characters\n");
      userChoice->minSpecial=getInputValue(userChoice->maxSize);
      if (userChoice->minSpecial!=0) {
        userChoice->specialAllowed=1;
      }
    }
    else if (choice==7) {
      if (userChoice->lowerAllowed==1) {
        userChoice->lowerAllowed=0;
        userChoice->minLower=0;
      }
      else {
        userChoice->lowerAllowed=1;
      }
    }
    else if (choice==8) {
      if (userChoice->upperAllowed==1) {
        userChoice->upperAllowed=0;
        userChoice->minUpper=0;
      }
      else {
        userChoice->upperAllowed=1;
      }
    }
    else if (choice==9) {
      if (userChoice->numberAllowed==1) {
        userChoice->numberAllowed=0;
        userChoice->minNumber=0;
      }
      else {
        userChoice->numberAllowed=1;
      }
    }
    else if (choice==10) {
      if (userChoice->specialAllowed==1) {
        userChoice->specialAllowed=0;
        userChoice->minSpecial=0;
      }
      else {
        userChoice->specialAllowed=1;
      }
    }
    choice=displayPassRules(userChoice);
  }
  return 0;
}

int displayPassRules(choiceType* userChoice) {
  int choice;
  int result;
  printf("\nPlease select an option\n");
  printf("(1) Modify the Minimum Password Length");
  if (userChoice->minSize==0) {
    printf("\t\t\t (Minimum Length currently not set)\n");
  }
  else {
    printf("\t\t\t (Minimum Lenght = %i)\n",userChoice->minSize);
  }
  printf("(2) Modify the Maximum Password Length.");
  if (userChoice->maxSize==0) {
    printf("\t\t\t (Maximum Length current not set)\n");
  }
  else {
    printf("\t\t\t (Maximum Length = %i)\n",userChoice->maxSize);
  }
  printf("(3) Modify the number of REQUIRED lowercase characters\t (Currently passwords require at least %i lowercase characters)\n",userChoice->minLower);
  printf("(4) Modify the number of REQUIRED UPPERCASE characters\t (Currently passwords require at least %i UPPERCASE characters)\n",userChoice->minUpper);
  printf("(5) Modify the number of REQUIRED numbers\t\t (Currently passwords require at least %i numbers)\n",userChoice->minNumber);
  printf("(6) Modify the number of REQUIRED special characters\t (Currently passwords require at least %i special characters)\n",userChoice->minSpecial);
  if (userChoice->lowerAllowed) {
    printf("(7) Don't allow any lowercase characters to be used\n");
  }
  else {
    printf("(7) Allow lowercase characters to be used\n");
  }
  if (userChoice->upperAllowed) {
    printf("(8) Don't allow any UPPERCASE characters to be used\n");
  }
  else {
    printf("(8) Allow UPPERCASE characters to be used\n");
  }
  if (userChoice->numberAllowed) {
    printf("(9) Don't allow any numbers to be used\n");
  }
  else {
    printf("(9) Allow numbers to be used\n");
  }
  if (userChoice->specialAllowed) {
    printf("(10)Don't allow any special characters to be used\n");
  }
  else {
    printf("(10)Allow special characters to be used\n");
  } 
  printf("(11)Go back to the previous menu\n");

  choice=getChoice(11);
  return choice;
}


/////////////////////////////////////////////////////////////////////////////////////////////////
//Gets the number value for min/max password size and number of required upper/lower/special/number
//Yes, it's a lot like getUserChoice(), but I felt it was easier to make a special function rather than
//modify getUserChoice
//If maxChoice==0, then it isn't checked, (I know weird right, but 0 is my "not set" value)
int getInputValue(int maxChoice) {
  int choice;
  char userInput[MAXUSERINPUT];
  choice = -1;
  printf("<enter value>:");
  while (choice==-1) {
    fgets(userInput,MAXUSERINPUT-1,stdin);
    if (userInput!=NULL) {
      choice = atoi(userInput);
      if ((maxChoice!=0)&&(choice > maxChoice)) {
        printf("Sorry, that value is too large.  The maximum value is %i\n",maxChoice);
        choice=-1;
      }
      else if (choice<0) {
        choice=-1;
      }
      if (choice==-1) {
        printf("Please enter in your value\n");
        printf("<enter value>:");
      }
    }
    rewind(stdin);
  }
  return choice;
}

int passMangle(choiceType* userChoice) {
  int choice;
  int result;
  choice=displayPassMangle();
  while (choice!=6) {
    if (choice==1) {
      ruleGuidedMain(userChoice);
    }
    else if (choice==2) {
      manuallyAddRule(userChoice);
    }
    else if (choice==3) {
      deleteRule(userChoice);
    }
    else if (choice==4) {
      moveRule(userChoice);
    }
    else if (choice==5) {
      displayRules(userChoice);
    }
    choice=displayPassMangle();
  }
  return 0;
}

int displayPassMangle() {
  int choice;
  int result;
  printf("\nPlease select an option\n");
  printf("(1) Add a new rule, (Menu Driven)\n");
  printf("(2) Manually add a new rule\n");
  printf("(3) Delete a rule\n");
  printf("(4) Change the order in which rules will be run\n");
  printf("(5) Display the current rules\n");
  printf("(6) Go back to the previous menu\n");

  choice=getChoice(6);
  return choice;
}

int displayRules(choiceType* userChoice) {
  listType *tempList;
  ruleType *tempRule;
  char userInput[MAXUSERINPUT];
  int count;
  
  count=1;
  tempList=userChoice->userRules;
  printf("\n------------ALL CURRENTLY CONFIGURED JtR RULES IN EXECUTION ORDER------------\n");  

  while (tempList!=NULL) {
    tempRule=tempList->value;
    printf("(%i) ",count);
    while (tempRule!=NULL) {
      printf("%s",tempRule->desc);
      if ((tempRule->next!=NULL)&&(tempRule->next->desc[0]!='\0')) {
        printf(", ");
      }
      tempRule=tempRule->next;
    }
    printf("\n");
    if (tempList->comment[0]!='\0') {
      printf("COMMENT: %s\n",tempList->comment);
    }
    printf("\n");
    tempList=tempList->next;
    count++;
  }
  printf("\n<Press Enter to continue>:");
  fgets(userInput,MAXUSERINPUT-1,stdin);  
  return 0;
}

int manuallyAddRule(choiceType* userChoice) {
  int done;
  int working;         //Used to say that there is a value to substitute in the user input string
  int size;            //Used to strip off the return character
  int choice;
  ruleType *tempRule;  //Used to add new rules onto the datastructure
  listType *tempList;  //used to add a new list struct onto the end of the current list
  listType *curList;   //used to traverse the current rule lists
  char userInput[100]; //the user input for the rule they want
  char tempHolder[100];//Added this since I was uncomfortable doing a strncpy where the to and from strings were the same, (even though using different spots)
  char *tempChar;      //used to parse the userinput

  curList=userChoice->userRules;
  tempRule = new ruleType;
  tempList = new listType;
  tempList->next=NULL;
 
  //--------Add a new List node----------//
  if (curList==NULL) {
    curList=tempList;
    userChoice->userRules=tempList;
  }
  else {
    while (curList->next!=NULL) {
      curList=curList->next;
    }
    curList->next=tempList;
    curList=curList->next;
  }
  curList->value=tempRule;

  //--------Get the user input----------//
  printf("Please type in the JtR formatted rule you wish to use.  To finish it, just hit <enter>\n");
  printf("Note: this parser does not typecheck the rule you type so any errors in it will cause JtR to fail when you attempt to run it with this config file\n");
  printf("Note: your password policy rules, (such as all passwords must contain at least 1 uppercase and 1 lowercase), will be added to your rule\n");
  printf("To take advantage of the macros provided by this config generator, just use the following for your expansion rules\n");
  printf("[l]  will replace it with the lowercase set defined in this config generator\n");
  printf("[u]  will replace it with the uppercase set defined in this config generator\n");
  printf("[d]  will replace it with the digit set defined in this config generator\n");
  printf("[s]  will replace it with the special character set defined in this config generator\n");
  printf("\n<enter rule>: ");
  fgets(userInput,99,stdin);
  size=strlen(userInput);
  userInput[size-1]='\0';
  strncpy(tempRule->desc,userInput,99);

  //-----Parse the user input for replacement values-----------/
  done=0;
  while (!done) {
    working=0;
    tempChar=strchr(userInput,'[');  //check start bracket
    while ((!working)&&(tempChar!=NULL)) {
      if (((tempChar[1])!='\0')&&((tempChar[2])!='\0')) { //makes sure that we don't overflow
        if ((tempChar[2])==']') { //check end bracket
          if ((tempChar[1])=='l') {
            working=1;
          }
          else if ((tempChar[1])=='u') {
            working=2;
          }
          else if ((tempChar[1])=='d') {      
            working=3;
          }
          else if ((tempChar[1])=='s') {
            working=4;
          }
        }
      }
      if (!working) {
        tempChar=strchr(tempChar+1,'[');
      }
    }
    tempRule->addType=working;
    if (working) {
      tempChar[0]='\0';
      strncpy(tempRule->jtrRule,userInput,99);
      if (tempChar[4]=='\0') {
        done=1;
        tempRule->next=NULL;
      }
      else { //more to parse
        strncpy(tempHolder,tempChar+3,99);
        strncpy(userInput,tempHolder,99);
        tempRule->next=new ruleType;
        tempRule=tempRule->next;
        tempRule->desc[0]='\0';
      }
    }
    else {
      done=1;
      tempRule->next=NULL;
      strncpy(tempRule->jtrRule,userInput,99);
    }
  } //end while loop
 
  //--Get comment if the user wants to add one------//
  printf("\nDo you want to add a comment?  (Trust me, they help)\n");
  printf("(1) Yes\n");
  printf("(2) No\n");
  choice=getChoice(2);
  if (choice==1) {
    printf("Please enter your comment.  To finish, just hit <enter>\n");
    printf("<Comment>: ");
    fgets(userInput,99,stdin);
    size=strlen(userInput);
    userInput[size-1]='\0';
    strncpy(curList->comment,userInput,99);   
  }
  else {
    curList->comment[0]='\0';
  } 
  return 0;
}

int deleteRule(choiceType* userChoice) {
  int count;
  int choice;
  listType *tempList;
  ruleType *tempRule;
  printf("\nPlease type the line number of the rule you want to delete\n\n");
  count=1;  
  tempList=userChoice->userRules;
  while (tempList!=NULL) {
    tempRule=tempList->value;
    printf("(%i) ",count);
    while (tempRule!=NULL) {
      printf("%s",tempRule->desc);
      if ((tempRule->next!=NULL)&&(tempRule->next->desc[0]!='\0')) {
        printf(", ");
      }
      tempRule=tempRule->next;
    }
    printf("\n");
    if (tempList->comment[0]!='\0') {
      printf("COMMENT: %s\n",tempList->comment);
    }
    printf("\n");
    tempList=tempList->next;
    count++;
  }
  printf("(%i) Don't delete anything.  Go back to previous menu\n\n",count);
  choice = getChoice(count);
  if (choice!=count) {
    tempList=userChoice->userRules;
    count=2;
    if (choice==1) {
      userChoice->userRules=userChoice->userRules->next;
    }
    else {
      while ((count!=choice)&&(tempList->next!=NULL)) {
        tempList=tempList->next;
        count++;
      }
      if (tempList->next!=NULL) {
        tempList->next=tempList->next->next;
      }
    }
  } 
  return 0;
}

int moveRule(choiceType* userChoice) {
  int count;
  int choice;
  int moveTo;
  listType *tempList;
  listType *tempList2;
  ruleType *tempRule;
  printf("\nPlease type the line number of the rule you want to move.\n");
  printf("BTW, Yes the GUI sucks.  If more people use this I might update it to something you would see in the late 1990's\n\n");
  count=1;
  tempList=userChoice->userRules;
  while (tempList!=NULL) {
    tempRule=tempList->value;
    printf("(%i) ",count);
    while (tempRule!=NULL) {
      printf("%s",tempRule->desc);
      if ((tempRule->next!=NULL)&&(tempRule->next->desc[0]!='\0')) {
        printf(", ");
      }
      tempRule=tempRule->next;
    }
    printf("\n");
    if (tempList->comment[0]!='\0') {
      printf("COMMENT: %s\n",tempList->comment);
    }
    printf("\n");
    tempList=tempList->next;
    count++;
  }
  printf("(%i) Go back to previous menu\n\n",count);
  choice = getChoice(count);
  if (choice!=count) {
    printf("\nPlease type the line number you would like to move the rule to\n");
    moveTo=getChoice(count-1);

    //-------Removes the move item from the List selection, will reinsert it afterwards at new pos------//
    tempList=userChoice->userRules;
    if (choice==1) {
      userChoice->userRules=userChoice->userRules->next;
    }
    else {
      count=1;   
      while ((tempList!=NULL)&&(count!=choice-1)) {
        tempList=tempList->next;
        count++;
      }
      tempList2 = tempList;
      tempList=tempList->next;
      if (tempList2->next!=NULL) {
        tempList2->next=tempList2->next->next;
      }
      else {
        tempList2->next=NULL;
      }
    }
    printf("\n so far so good\n");
    //----------Reinsert the move item in its new location--------------------------------------//
    if (moveTo==1) {
      tempList->next=userChoice->userRules;
      userChoice->userRules=tempList;
    }
    else {
      count=1;
      tempList2=userChoice->userRules;
      while ((tempList2->next!=NULL)&&(count!=moveTo-1)) {
        tempList2=tempList2->next;
        count++;
      } 
      if (tempList2!=NULL) {
        tempList->next=tempList2->next;
      }
      else {
        tempList->next=NULL;
      }
      tempList2->next=tempList; 
    }
  }
  return 0;
}

int saveConfig(choiceType* userChoice) {
  char userInput[100];
  char fileName[100];
  FILE *saveFile;
  int size;
  listType *tempList;
  ruleType *tempRule;

  printf("\nThis will save your current config so you can load and modify it later\n");
  printf("Please enter the filename you want to save this as, or just hit enter to go back to the previous menu\n");
  printf("\n<filename>:");
  fgets(userInput,99,stdin);
  if (userInput[0]=='\n') {  //The user does not want to save the config
    return 0;
  }
  size=strlen(userInput);
  userInput[size-1]='\0';
  strncpy(fileName,userInput,99);
  saveFile=fopen(fileName,"w");
  if (saveFile==NULL) {
    printf("ERROR: Could not open %s\n",fileName);
    return -1;
  }
  fprintf(saveFile,"jtrMakeConfig Save File\nAuthor:Matt Weir\nContact Info: weir@cs.fsu.edu\nVersion: 1.0\n");
  //----------Start writing out all the non Rule Variables, (and there are a lot of them)------//
  fprintf(saveFile,"%i %i %i %i %i %i\n",userChoice->maxSize,userChoice->minSize,userChoice->numberAllowed,userChoice->specialAllowed,
    userChoice->lowerAllowed,userChoice->upperAllowed);
  fprintf(saveFile,"%i %i %i %i\n",userChoice->minNumber,userChoice->minUpper,userChoice->minSpecial,userChoice->minLower);
  fprintf(saveFile,"<special>%s\n",userChoice->specialSet);
  fprintf(saveFile,"<lower>%s\n",userChoice->lowerSet);
  fprintf(saveFile,"<upper>%s\n",userChoice->upperSet);
  fprintf(saveFile,"<number>%s\n",userChoice->numberSet);  
  //---------Write out the rules, hopefully the user didn't create a rule with a xml tag in it----//
  tempList=userChoice->userRules;
  while (tempList!=NULL) {
    fprintf(saveFile,"<newRule>\n");
    fprintf(saveFile,"<comment>%s\n",tempList->comment);
    tempRule=tempList->value;
    while (tempRule!=NULL) {
      fprintf(saveFile,"<rulePart>\n");
      fprintf(saveFile,"<addType>%i\n",tempRule->addType);
      fprintf(saveFile,"<desc>%s\n",tempRule->desc);
      fprintf(saveFile,"<jtrRule>%s\n",tempRule->jtrRule);
      fprintf(saveFile,"</rulePart>\n");
      tempRule=tempRule->next;
    }
    fprintf(saveFile,"</newRule>\n");
    tempList=tempList->next;
  }
  fclose(saveFile);
  return 0;
}


int loadConfig(choiceType* userChoice) {
  char userInput[100];
  char fileName[100];
  FILE *loadFile;
  int size;
  listType *tempList;
  listType *tempList2;
  ruleType *tempRule;
  ruleType *tempRule2;
  char tempChar;
  char tempString[200];
  int i;

  printf("\nThis will load a saved config file\n");
  printf("Please enter the filename of the config file you want to load, or just hit enter to go back to the previous menu\n");
  printf("Yah, it would be nice to have a file browser to use.  It would also be nice if your mom wasn't so fat, but we all make do with what we have.\n");
  printf("\n<filename>:");
  fgets(userInput,99,stdin);
  if (userInput[0]=='\n') {  //The user does not want to save the config
    return 0;
  }
  size=strlen(userInput);
  userInput[size-1]='\0';
  strncpy(fileName,userInput,99);
  loadFile=fopen(fileName,"r");
  if (loadFile==NULL) {
    printf("ERROR: Could not open %s\n",fileName);
    return -1;
  }
  //----First get rid of the header info, may want to check the version number at a later point if I change how the save file is parsed--//
  fgets(tempString,199,loadFile);
  fgets(tempString,199,loadFile);
  fgets(tempString,199,loadFile);
  fgets(tempString,199,loadFile);

  //----Read in the number values------------------------//
  userChoice->maxSize=getLoadNumber(loadFile);
  userChoice->minSize=getLoadNumber(loadFile);
  userChoice->numberAllowed=getLoadNumber(loadFile);
  userChoice->specialAllowed=getLoadNumber(loadFile);
  userChoice->lowerAllowed=getLoadNumber(loadFile);
  userChoice->upperAllowed=getLoadNumber(loadFile);
  userChoice->minNumber=getLoadNumber(loadFile);
  userChoice->minUpper=getLoadNumber(loadFile);
  userChoice->minSpecial=getLoadNumber(loadFile);
  userChoice->minLower=getLoadNumber(loadFile); 

  //--Read in the character combo values---------------------//
  fgets(tempString,199,loadFile);
  size=strlen(tempString);
  tempString[size-1]='\0';
  strncpy(userChoice->specialSet,tempString+9,99);
  fgets(tempString,199,loadFile);
  size=strlen(tempString);
  tempString[size-1]='\0';
  strncpy(userChoice->lowerSet,tempString+7,99);
  fgets(tempString,199,loadFile);
  size=strlen(tempString);
  tempString[size-1]='\0';
  strncpy(userChoice->upperSet,tempString+7,99);
  fgets(tempString,199,loadFile);
  size=strlen(tempString);
  tempString[size-1]='\0';
  strncpy(userChoice->numberSet,tempString+8,99);

  //--Now read in all the rules-----------------------------//
  fgets(tempString,199,loadFile);
  userChoice->userRules=NULL;
  tempList2=NULL;
  while (!feof(loadFile)) {
    if (strncmp(tempString,"<newRule>\n",99)==0) { //insert the new node
      printf("So far so good\n");
      tempList2=new listType;
      if (userChoice->userRules==NULL) {
        userChoice->userRules=tempList2;
      }
      else {
        tempList=userChoice->userRules;
        while (tempList->next!=NULL) {
          tempList=tempList->next;
        }
        tempList->next=tempList2;
      }  
      fgets(tempString,199,loadFile);
      size=strlen(tempString);
      tempString[size-1]='\0';
      strncpy(tempList2->comment,tempString+9,99);
      tempList2->value=NULL;
    }
    else if ((strncmp(tempString,"<rulePart>\n",99)==0)&&(tempList2!=NULL)) {
      printf("adding rule\n");
      tempRule2= new ruleType;
      tempRule2->next=NULL;
      if (tempList2->value==NULL) {  //insert the new rule node
        tempList2->value=tempRule2;
      }
      else {
        tempRule=tempList2->value;
        while (tempRule->next!=NULL) {
          tempRule=tempRule->next;
        }
        tempRule->next=tempRule2;
      } 
      fgets(tempString,199,loadFile);
      size=strlen(tempString);
      tempString[size-1]='\0';
      tempRule2->addType=atoi(tempString+9);
      fgets(tempString,199,loadFile);
      size=strlen(tempString);
      tempString[size-1]='\0';
      strncpy(tempRule2->desc,tempString+6,99);
      printf("%s\ntest",tempRule2->desc);
      fgets(tempString,199,loadFile);
      size=strlen(tempString);
      tempString[size-1]='\0';
      strncpy(tempRule2->jtrRule,tempString+9,99);
    }
    else if (strncmp(tempString,"</newRule>\n",99)==0) {
      tempList2=NULL;
    }
    fgets(tempString,199,loadFile);
  }
  fclose(loadFile);         
  return 0;
}

int getLoadNumber(FILE *loadFile) {
  int i;
  char tempChar;
  char tempString[100]; //could make it smaller, but I've been useing 100 for my array sizes everywhere else.
  
  tempChar=fgetc(loadFile);
  i=0;
  while ((!feof(loadFile))&&(tempChar!=' ')&&(tempChar!='\n')) {
    tempString[i]=tempChar;
    tempChar=fgetc(loadFile);
    i++;
  }
  tempString[i]='\0';
  i=atoi(tempString);    
  return i;
}

int createJtr(choiceType* userChoice) {
  char userInput[100];
  char fileName[100];
  FILE *saveFile;
  FILE *topFile;
  FILE *bottomFile;
  int size;
  listType *tempList;
  ruleType *tempRule;
  char tempLine[300];
  char prefix[100];

  printf("\nThis will create a new John the Ripper config file\n");
  printf("Please enter the filename you want to save this as, (normally it is called \"john.conf\"), or just hit enter to go back to the previous menu\n");
  printf("\n<filename>:");
  fgets(userInput,99,stdin);
  if (userInput[0]=='\n') {  //The user does not want to save the config
    return 0;
  }
  size=strlen(userInput);
  userInput[size-1]='\0';
  strncpy(fileName,userInput,99);
  saveFile=fopen(fileName,"w");
  if (saveFile==NULL) {
    printf("ERROR: Could not open %s\n",fileName);
    return -1;
  }
  topFile=fopen("./supportFiles/startDoc.txt","r");
  bottomFile=fopen("./supportFiles/endDoc.txt","r");
  if ((topFile==NULL)||(bottomFile==NULL)) {
    printf("Error: Could not open files in the ./supportFiles/ directory\n");
    return -1;
  }
  printf("\nStarting to create config file...\n");
  fprintf(saveFile,"# This config file was generated by jtrMakeConfig version 1.0\n");
  fprintf(saveFile,"# Author Matt Weir\n");
  fprintf(saveFile,"# Contact Info:weir@cs.fsu.edu\n\n");
  fgets(tempLine,299,topFile);
  while (!feof(topFile)){
    fprintf(saveFile,"%s",tempLine);
    fgets(tempLine,299,topFile);
  }
  printf("Saving user configured rules...\n");

  //-----------This is where the fun stuff happens, saving the actual config-----------//
  //--determine prefix info---//
  prefix[0]='\0';
  if (userChoice->maxSize!=0) {
    snprintf(tempLine,200,"<%d",userChoice->maxSize);
    strncat(prefix,tempLine,10);
  }
  if (userChoice->minSize!=0) {
    snprintf(tempLine,200,">%d",userChoice->minSize);
    strncat(prefix,tempLine,10);
  }
  if (userChoice->numberAllowed==0) {
    snprintf(tempLine,200,"![%s]",userChoice->numberSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->specialAllowed==0) {
    snprintf(tempLine,200,"![%s]",userChoice->specialSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->lowerAllowed==0) {
    snprintf(tempLine,200,"![%s]",userChoice->lowerSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->upperAllowed==0) {
    snprintf(tempLine,200,"![%s]",userChoice->upperSet);
    strncat(prefix,tempLine,100);
  }
  //I need to find a better way to do this, but JtR is a pain with exclude rules
  //It uses the user defined char sets if there min number is 1, otherwise it uses the JtR
  //character list, it's a hack, but otherwise if you have a minimum of two upper character letters
  //It would allow TTest, but not TEst, aka the way the rules expand it doesn't allow me to select from
  //a group for N>1.
  if (userChoice->minNumber==1) {
    snprintf(tempLine,200,"%%%d[%s]",userChoice->minNumber,userChoice->numberSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minLower==1) {
    snprintf(tempLine,200,"%%%d[%s]",userChoice->minLower,userChoice->lowerSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minUpper==1) {
    snprintf(tempLine,200,"%%%d[%s]",userChoice->minUpper,userChoice->upperSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minSpecial!=0) {
    snprintf(tempLine,200,"%%%d[%s]",userChoice->minSpecial,userChoice->specialSet);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minNumber>1) {
    snprintf(tempLine,200,"%%%d?d",userChoice->minNumber);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minLower>1) {
    snprintf(tempLine,200,"%%%d?l",userChoice->minLower);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minUpper>1) {
    snprintf(tempLine,200,"%%%d?u",userChoice->minUpper);
    strncat(prefix,tempLine,100);
  }
  if (userChoice->minSpecial>1) {
    snprintf(tempLine,200,"%%%d?X",userChoice->minNumber);
    strncat(prefix,tempLine,100);
  }
  //---Done with prefix info, start adding the actual rules---------------------//
  tempList=userChoice->userRules;
  while (tempList!=NULL) {
    tempRule=tempList->value;
    if (tempList->comment[0]!='\0') {
      snprintf(tempLine,200,"# %s\n",tempList->comment);
      fprintf(saveFile,"%s",tempLine);
    }
    fprintf(saveFile,"%s",prefix);
    //--Note, could add the user readable description as well, but I figure the explicit comment if set will be enough --//
    while (tempRule!=NULL) {
      fprintf(saveFile,"%s",tempRule->jtrRule);
      if (tempRule->addType==1) {
        fprintf(saveFile,"[%s]",userChoice->lowerSet);
      }
      if (tempRule->addType==2) {
        fprintf(saveFile,"[%s]",userChoice->upperSet);
      }
      if (tempRule->addType==3) {
        fprintf(saveFile,"[%s]",userChoice->numberSet);
      }
      if (tempRule->addType==4) {
        fprintf(saveFile,"[%s]",userChoice->specialSet);
      }
      tempRule=tempRule->next;
    }
    fprintf(saveFile,"\n");
    tempList=tempList->next;
  }

  //-----------End of inserting the user defined config info -------------------//
    
  printf("Saving end of the config file...\n");
  fgets(tempLine,299,bottomFile);
  while (!feof(bottomFile)) {
    fprintf(saveFile,"%s",tempLine);
    fgets(tempLine,299,bottomFile);
  }
  printf("Done saving the config file!!!\n\n");
  fclose(topFile);
  fclose(bottomFile);
  fclose(saveFile);
  return 0;
}

int ruleGuidedMain(choiceType* userChoice) {
  listType *tempList;
  listType *moveList;
  ruleType *tempRule;
  ruleType *passRule;
  int choice;
  int result;

  tempList=new listType;
  tempList->comment[0]='\0';
  tempList->value=NULL;
  tempList->next=NULL;
  result=-1;

  choice=displayMainGuide(tempList);
  while ((choice!=8)&&(choice!=7)) {
    passRule=new ruleType;
    passRule->next=NULL;
    passRule->jtrRule[0]='\0';
    passRule->desc[0]='\0';
    result=-1;
    if (choice==1) {   //Case Manglinge
      result=caseMangleRule(passRule);
    }
    else if (choice==2) {  //Insertion of characters
      result=insertMangleRule(passRule);
    }
    else if (choice==3) {  //Switch characters
      result=replaceMangleRule(passRule);
    }
    else if (choice==4) {  //Delete Characters
      result=deleteMangleRule(passRule); 
    }
    else if (choice==5) {  //Assorted Rules
      result=assortedMangleRule(passRule);
    }
    else if (choice==6) {   //Add Comment
      addCommentRule(tempList); 
    }
    else if (choice==9) {  //Help
      ruleHelp();
    }
    if ((result!=-1)&&(passRule!=NULL)) { //add the sub-rule
      if (tempList->value==NULL) {
        tempList->value=passRule;
        tempRule=tempList->value;
      }
      else {
        tempRule->next=passRule;
        tempRule=tempRule->next;
      }
    }
    choice=displayMainGuide(tempList);
  }
  if (choice==7) {  //save the rule
    if (tempList->value==NULL) {
      printf("But you haven't even entered anything yet!?  Going back to the previous menu while you make up your mind\n");
      return 0;
    }
    moveList=userChoice->userRules;
    if (moveList==NULL) {
      userChoice->userRules=tempList;
    }
    else {
      while (moveList->next!=NULL) {
        moveList=moveList->next;
      }
      moveList->next=tempList;
    }
  }
  return 0;
}


int displayMainGuide(listType *tempList) {
  int choice;
  int result;
  ruleType *tempRule;
 
  tempRule=tempList->value;
  printf("\n-----------------Welcome to the JtR rule creation walkthrough-----------------------\n");
  printf("Please Note: All sub-parts of the rule are executed in the order that you enter them\n");
  printf("So if you want to create the rule that will turn \"password\" into \"Password$1\", you would enter the rules in the following order:\n");
  printf("-capitalize the first letter\n");
  printf("-add a \"$\" to the end of the word\n");
  printf("-add a \"1\" to the end of the word\n");
  printf("Rules won't actually be created until you confirm them\n");
  printf("Here is your current rule:\n");
  printf("--------------------------------------\n");
  while (tempRule!=NULL) {
    if (tempRule->desc[0]!='\0') {
      printf("%s",tempRule->desc);
      tempRule=tempRule->next;
      if (tempRule!=NULL) {
        printf(", ");
      }
    }
    else {
      tempRule=tempRule->next;
    }
  }
  printf("\n--------------------------------------\n");

  printf("Please select the mangling rule you want to add to the current rule\n");
  printf("(1) Add a case mangling rule                 - (password -> PaSSWoRD)\n");
  printf("(2) Add a value to the dictionary word       - (password -> 12password12)\n");
  printf("(3) Replace letters in the dictionary word   - (password -> p@$$word)\n");
  printf("(4) Delete letters from the dictionry word   - (password -> pssword)\n");
  printf("(5) Collection of other rules you might like - (password -> drowssap)\n");
  printf("(6) Add a comment to your rule               - (Comments are good.  You won't regret it)\n");
  printf("(7) Save your rule\n");
  printf("(8) Cancel and go back to the previous menu (WARNING WILL NOT SAVE YOUR RULE!)\n");
  printf("(9) Help and general thoughts on rule creation, (if I get around to writing this)\n");
  choice=getChoice(9);
  return choice;
}

int ruleHelp() {
  printf("\n-------------------Help, aka you are smarter than most people because you are actually reading the FAQ------------------\n");
  printf("\n(Q) How do I add two digits to the end of a dictionary word?\n");
  printf("(A) If you want to add all digits, aka 00-99 then simply make two rules\n");
  printf("     --Add a digit to the end of the dictionary word\n");
  printf("     --Add a digit to the end of the dictionary word\n");
  printf("\n(Q) What if I want to only add certain numbers like dates?\n");
  printf("(A) This is a little bit harder, and unless I add support for it, will probably require several different rules\n");
  printf("    For example if you want to add support for 1900-1999 and 2000-2009 you could create two rules\n");
  printf("      --First Rule:  Add \"19\" to the end of the dictionary word\n");
  printf("      --First Rule:  Add a digit to the end of the dictionary word\n");
  printf("      --First Rule:  Add a digit to the end of the dictionary word\n");
  printf("      --Second Rule: Add \"200\" to the end of a dictionary word\n");
  printf("      --Second Rule: Add a digit to the end of the dictionary word\n");
  printf("    In future versions I'll see what I can do to make this easier since dates are very commonly used in passwords\n");
  printf("\n(Q) What are the most common word mangling rules that I should include?\n");
  printf("(A) That really depends on if a password policy exists or not\n");
  printf("    If no password policy is being used, first make sure you have a NOOP rule, (included by default so it's there if you haven't deleted it)\n");
  printf("    Also, it's a good idea to always add the lowercase sub-rule first, even if you want to try upper case letters\n");
  printf("    This is because some input dictionaries vary on if the first letter is stored as uppercase or not\n");
  printf("    So if you want to uppercase the last letter, first add \"losercase everything\", then \"uppercase the last letter\"\n");
  printf("    You might want to ignore this sometimes though if the input dictionary has some usefull capitalization in it, such as \"passWord\"\n");
  printf("    You should have a rule that adds 1 digit to the end, and another rule that adds two digits to the end.  These are the most common passwords\n");
  printf("    If a letter is going to be capitalized, it will almost always be the first letter\n");
  printf("    Having special characters then numbers at the end of the password, (\"password$5\") is much more common than the reverse\n");
  printf("    If somone puts something before their password, it usually is a number, (\"12password\")\n");
  printf("    To get a better breakdown of the different rules, check out the talk I gave at Shmoocon, \"Smarter Password Cracking\"\n");
  printf("    www.shmoocon.org  <-Yes, that is a bit of blatent self promotion.  It's not like I'm being paid, so I might as well pump up my ego instead ;)\n");
  return 0;
}

int insertMangleRule(ruleType *tempRule) {
  int choice;
  int size;
  char jtrPos;
  char userInput[100];
  char prefix[20];
  ruleType *nextRule;
  ruleType *nextRule2;
  char *tempChar;
  int found;
  int i;
  int j;
  char tempHolder[2];

  printf("\n----------------------------Insert Characters---------------------------------------\n");
  printf("(1) Add a value to the end of a dictionary word                   -(password->password12)\n");
  printf("(2) Add a value to the start of a dictionary word                 -(password->12password)\n");
  printf("(3) Add a value to a certain location of the dictionary word      -(password->p1assword)\n");
  printf("(4) Go back to the previous menu\n");
  choice=getChoice(4);
  if (choice==4) {
    return -1;
  }
  else {
    //------------First handle the prefix info-----------------------//
    if (choice==1) {
      strncpy(prefix,"$",3);
      strncpy(tempRule->desc,"Append ",10);
    }
    else if (choice==2) {
      strncpy(prefix,"^",3);
      strncpy(tempRule->desc,"Prefix ",10);
    }
    else if (choice==3) {
      printf("\nPlease enter which position you want to insert the string.  Note, if the position is longer than the word, it will not be inserted\n");
      printf("The numbering starts at 0, and the maxvalue is 35\n\n");
      size=getInputValue(35); //JtR only supports up to position #35
      jtrPos=getJtrPos(size);
      snprintf(prefix,10,"i%c",jtrPos);
      snprintf(tempRule->desc,20,"Insert at Pos \"%d\" ",size);
      printf("\nBug alert! If you are inserting more than one character, please do it in reverse.  I might fix this in the next version\n");
      printf("\nAka if you want to insert '123' then type '321'.  This is because it inserts each char individual into the position you specified\n");
    }
    //-------------Now handle the actual inserting, dealing with ranges is a pain in the butt------------------//
    tempRule->next=NULL;
    tempRule->addType=0;
    nextRule=tempRule;
    printf("\nPlease type in the value you want to insert.\n");
    printf("If you want to use one of the built in character list ranges, type the following\n");
    printf("[l]  will replace it with the lowercase set defined in this config generator\n");
    printf("[u]  will replace it with the uppercase set defined in this config generator\n");
    printf("[d]  will replace it with the digit set defined in this config generator\n");
    printf("[s]  will replace it with the special character set defined in this config generator\n");
    printf("You can also create your own list by putting the values between '[' ']', such as [aeiouy] to insert a vowel\n"); 
    printf("Example:[d][d]     <-will add two digits on to the end of the password, aka 'password99'");
    printf("*If you want to insert a '\\', or a '[', or a ']', or a '-', please put a '\\' before it, aka '\\-'\n\n");
    printf("<enter value to insert>:");
    fgets(userInput,99,stdin);
    size=strlen(userInput);
    userInput[size-1]='\0';
    size--;
    strncat(tempRule->desc,userInput,99); 


    //--parse the user input-----------------------//
    i=0;
    j=0;
    tempHolder[1]='\0';
    for (i;i<size;i++) { 
      if ((i<size-2)&&(userInput[i]=='[')&&(userInput[i+1]=='l')&&(userInput[i+2]==']')) {  //insert a lowercase letter
        strncpy(nextRule->jtrRule,prefix,20);
        nextRule->addType=1;
        i=i+2;
        if (userInput[i+1]!='\0') { //not the end
          nextRule2=new ruleType;
          nextRule2->desc[0]='\0';
          nextRule2->jtrRule[0]='\0';
          nextRule2->addType=0;
          nextRule2->next=NULL;
          nextRule->next=nextRule2;
          nextRule=nextRule->next;
        }         
      }
      else if ((i<size-2)&&(userInput[i]=='[')&&(userInput[i+1]=='u')&&(userInput[i+2]==']')) { //insert a uppercase letter
        strncpy(nextRule->jtrRule,prefix,20);
        nextRule->addType=2;
        i=i+2;
        if (userInput[i+1]!='\0') { //not the end
          nextRule2=new ruleType;
          nextRule2->desc[0]='\0';
          nextRule2->jtrRule[0]='\0';
          nextRule2->addType=0;
          nextRule2->next=NULL;
          nextRule->next=nextRule2;
          nextRule=nextRule->next;
        }
      }
      else if ((i<size-2)&&(userInput[i]=='[')&&(userInput[i+1]=='d')&&(userInput[i+2]==']')) { //insert a digit
        strncpy(nextRule->jtrRule,prefix,20);
        nextRule->addType=3;
        i=i+2;
        if (userInput[i+1]!='\0') { //not the end
          nextRule2=new ruleType;
          nextRule2->desc[0]='\0';
          nextRule2->jtrRule[0]='\0';
          nextRule2->addType=0;
          nextRule2->next=NULL;
          nextRule->next=nextRule2;
          nextRule=nextRule->next;
        }
      }
      else if ((i<size-2)&&(userInput[i]=='[')&&(userInput[i+1]=='s')&&(userInput[i+2]==']')) { //insert a special character
        strncpy(nextRule->jtrRule,prefix,10);
        nextRule->addType=4;
        i=i+2;
        if (userInput[i+1]!='\0') { //not the end
          nextRule2=new ruleType;
          nextRule2->desc[0]='\0';
          nextRule2->jtrRule[0]='\0';
          nextRule2->addType=0;
          nextRule2->next=NULL;
          nextRule->next=nextRule2;
          nextRule=nextRule->next;
        }
      } 
      else if (userInput[i]=='\\') {
        strncat(nextRule->jtrRule,prefix,20);
        tempHolder[0]=userInput[i];
        strncat(nextRule->jtrRule,tempHolder,10);
        i++;
        tempHolder[0]=userInput[i];
        strncat(nextRule->jtrRule,tempHolder,10);
      }
      else if (userInput[i]=='[') {
        strncat(nextRule->jtrRule,prefix,20);
        tempHolder[0]=userInput[i];
        strncat(nextRule->jtrRule,tempHolder,10);
        i++;
        while ((i<size)&&(userInput[i]!=']')) {
          tempHolder[0]=userInput[i];
          strncat(nextRule->jtrRule,tempHolder,10);
          i++;
          if ((userInput[i]==']')&&(userInput[i-1]=='\\')) {
            tempHolder[0]=userInput[i];
            strncat(nextRule->jtrRule,tempHolder,10);
            i++;
          }
        }
      }
      else {
        strncat(nextRule->jtrRule,prefix,20);
        tempHolder[0]=userInput[i];
        strncat(nextRule->jtrRule,tempHolder,20);
      }
    }
  }       
  return 0;
}

int caseMangleRule(ruleType *tempRule) {
  int choice;
  int size;
  char jtrPos;
  printf("\n-----------Add Case Mangling--------------------------\n\n");
  printf("(1) Convert everything to lowercase                   -(PassWord->password)\n");
  printf("(2) Convert everything to uppercase                   -(password->PASSWORD)\n");
  printf("(3) Capitalize the first letter                       -(password->Password)\n");
  printf("(4) Capitalize everything but the first letter        -(password->pASSWORD)\n");
  printf("(5) Toggle the case of all the characters             -(PassWord->pASSwORD)\n");
  printf("(6) Toggle the case of the last letter                -(password->passworD)\n");
  printf("(7) Toggle the case of a letter at a certain location -(password->pAssword)\n");
  printf("(8) Lowercase vowels, uppercase consonants            -(password->PaSSWoRD)\n");
  printf("(9) Swap case by keyboard position, (shift key)       -(password12->PASSWORD!@)\n");
  printf("(10) Go back to the previous menu\n");
  choice=getChoice(10); 
  if (choice==10) {
    return -1;
  }
  else {
    tempRule->next=NULL;
    tempRule->addType=0;
    if (choice==1) {
      strncpy(tempRule->desc,"Lowercase Everything",99);
      strncpy(tempRule->jtrRule,"l",99);
    }
    else if (choice==2) {
      strncpy(tempRule->desc,"Uppercase Everything",99);
      strncpy(tempRule->jtrRule,"u",99);
    }
    else if (choice==3) {
      strncpy(tempRule->desc,"Capitalize the first letter",99);
      strncpy(tempRule->jtrRule,"c",99); 
    }
    else if (choice==4) {
      strncpy(tempRule->desc,"Capitalize everything but the first letter",99);
      strncpy(tempRule->jtrRule,"C",99);
    }
    else if (choice==5) {
      strncpy(tempRule->desc,"Toggle the case of all letters",99);
      strncpy(tempRule->jtrRule,"t",99);
    }
    else if (choice==6) {
      strncpy(tempRule->desc,"Toggle the case of the last letter",99);
      strncpy(tempRule->jtrRule,"rT0r",99);
    }
    else if (choice==7) {
      printf("\nPlease enter the character position, (0,1,2,3...N), you want to toggle\n");
      printf("\nJohn the Ripper only supports a max character position of 35\n");
      size=getInputValue(35); //JtR only supports up to position #35
      jtrPos=getJtrPos(size);
      snprintf(tempRule->desc,99,"Toggle the case of the character at position %c",jtrPos);
      snprintf(tempRule->jtrRule,99,"T%c",jtrPos);
    }
    else if (choice==8) {
      strncpy(tempRule->desc,"Lowercase Vowels, Uppercase Consonants",99);
      strncpy(tempRule->jtrRule,"V",99);strncpy(tempRule->desc,"Lowercase Vowels, Uppercase Consonants",99);
    }
    else if (choice==9) {
      strncpy(tempRule->desc,"Swap Case of all Keyboard Values",99);
      strncpy(tempRule->jtrRule,"S",99);
    }
 
  }
  return 0;
}

///////////////////////////////////////////////////////////////////////
//To denote a location, JtR chooses 0-9, then A-Z
//Need to convert from user input to jtr form.
//Returns a character regardless
char getJtrPos(int size) {
  char returnVal;
  //--Yay Ascii
  if (size<10) {
    returnVal=48+size;
  }
  else {
    returnVal=55+size;
  }
  return returnVal;
}

int addCommentRule(listType *tempList) {
  char userInput[100];
  int size;

  printf("Please enter your comment.  To finish, just hit <enter>\n");
  printf("<Comment>: ");
  fgets(userInput,99,stdin);
  size=strlen(userInput);
  userInput[size-1]='\0';
  strncpy(tempList->comment,userInput,99);
  return 0;
}

int assortedMangleRule(ruleType *tempRule) {
  int choice;
  int size;
  char jtrPos;
  printf("\n-----------Assorted Mangling Rule that didn't fit elsewhere--------------------------\n");
  printf("--(I'll be honest, most of these rules except for duplicate are fairly worthless)----\n");
  printf("--(Aka, for pluralizing you could just add \"s\" to the end of the word)---------------\n\n");
  printf("(1) Reverse the word, (Who does this?!)                   -(password->drowssap)\n");
  printf("(2) Duplicate the word                                    -(password->passwordpassword)\n");
  printf("(3) Reflect the word, (I've never seen this one)          -(password->passworddrowssap)\n");
  printf("(4) Rotate the word left                                  -(password->asswordp)\n");
  printf("(5) Rotate the word right                                 -(password->dpasswor)\n");
  printf("(6) Pluralize, (lowercase only, only seems to add an s)   -(password->passwords)\n");
  printf("(7) Add \"ed\" to the end                                   -(password->passworded)\n");
  printf("(8) Add \"ing\" to the end                                  -(password->passwording)\n");
  printf("(9) Go back to the previous menu\n");
  choice=getChoice(9);
  if (choice==9) {
    return -1;
  }
  else {
    tempRule->next=NULL;
    tempRule->addType=0;
    if (choice==1) {
      strncpy(tempRule->desc,"Reverse the word",99);
      strncpy(tempRule->jtrRule,"r",99);
    }
    else if (choice==2) {
      strncpy(tempRule->desc,"Duplicate the word",99);
      strncpy(tempRule->jtrRule,"d",99);
    }
    else if (choice==3) {
      strncpy(tempRule->desc,"Reflect the word -Poser",99);
      strncpy(tempRule->jtrRule,"f",99);
    }
    else if (choice==4) {
      strncpy(tempRule->desc,"Rotate the word left",99);
      strncpy(tempRule->jtrRule,"{",99);
    }
    else if (choice==5) {
      strncpy(tempRule->desc,"Rotate the word right",99);
      strncpy(tempRule->jtrRule,"}",99);
    }
    else if (choice==6) {
      strncpy(tempRule->desc,"Pluralize",99);
      strncpy(tempRule->jtrRule,"p",99);
    }
    else if (choice==7) {
      strncpy(tempRule->desc,"Add \"ed\"",99);
      strncpy(tempRule->jtrRule,"P",99);
    }
    else if (choice==8) {
      strncpy(tempRule->desc,"Add \"ing\"",99);
      strncpy(tempRule->jtrRule,"I",99);
    }
  }
  return 0;
}

int replaceMangleRule(ruleType *tempRule) {
  int choice;
  int size;
  char jtrPos;
  char userInput[100];
  char userInput2[100];
  char iChar1;
  char iChar2;
  printf("\n----------Character Replacement---------------------------\n");
  printf("Please enter the character you want to replace, or just hit enter to go back to the previous menu\n\n");
  printf("<Enter Character>:");
  fgets(userInput,99,stdin);
  if (userInput[0]=='\n') {
    return -1;
  }
  printf("Please enter the character you want to replace '%c' WITH, or just hit enter to go back to the previous menu\n\n",userInput[0]);
  printf("<Enter Character>:");
  fgets(userInput2,99,stdin);
  if (userInput2[0]=='\n') {
    return -1;
  }
  tempRule->addType=0;
  tempRule->next=NULL;
  iChar1=userInput[0];
  iChar2=userInput2[0];
  snprintf(tempRule->desc,99,"Replace '%c' with '%c'",iChar1, iChar2);
  //--------need to deal with those pesky special characters--------------//
  if ((iChar1=='[')||(iChar1==']')||(iChar1=='\\')||(iChar1=='?')) {
    snprintf(tempRule->jtrRule,50,"s\\%c",iChar1);
  }
  else {
    snprintf(tempRule->jtrRule,50,"s%c",iChar1);
  }
  if ((iChar2=='[')||(iChar2==']')||(iChar2=='\\')||(iChar2=='?')) {
    snprintf(userInput,50,"\\%c",iChar2);
  }
  else {
    snprintf(userInput,50,"%c",iChar2);
  }
  strncat(tempRule->jtrRule,userInput,99);
  return 0;
}

int deleteMangleRule(ruleType *tempRule) {
  int choice;
  int size;
  char jtrPos;
  char userInput[100];
  printf("\n-----------Delete Characters from the Dictionary Word--------------------------\n");
  printf("(1) Delete the first character                   -(password->assword) hehe, assword\n");
  printf("(2) Delete the last character                    -(password->passwor)\n");
  printf("(3) Delete the character at position N           -(password->pssword)\n");
  printf("(4) Go back to the previous menu\n");
  choice=getChoice(4);
  if (choice==4) {
    return -1;
  }
  else {
    tempRule->addType=0;
    tempRule->next=NULL;
    if (choice==1) {
      strncpy(tempRule->desc,"Delete first character",50);
      strncpy(tempRule->jtrRule,"\\[",50);
    }
    else if (choice==2) {
      strncpy(tempRule->desc,"Delete last character",50);
      strncpy(tempRule->jtrRule,"\\]",50);
    }
    else if (choice==3) {
      printf("\nPlease enter the character position, (0,1,2,3...N), you want to delete\n");
      printf("\nJohn the Ripper only supports a max character position of 35\n");
      size=getInputValue(35); //JtR only supports up to position #35
      jtrPos=getJtrPos(size);
      snprintf(tempRule->desc,99,"Delete the character at '%d'",size);
      snprintf(tempRule->jtrRule,99,"D%c",jtrPos);
   }
 }
 return 0;
}


//Thank god I'm done for now.
//If I knew how much of a pain this would be I would have never started
//Heh, that's probably a good thing then.
//I've been doing some testing, but still I guarentee there are bugs in this
//The most likely areas, parsing user input, (aka if they add a lot of special characters such as '['
//And me not escaping those characters when I create rules
//I hope this is usefull, and if you find a bug, please let me know about it
//Matt Weir, weir@cs.fsu.edu 
