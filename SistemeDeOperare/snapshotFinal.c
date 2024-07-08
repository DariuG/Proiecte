//pt a gasi daca ex diferente intre cont unui folder intre 2 rulari
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define MAX_PATHL 500

char* statusFile; //fisierul in care retinem datele pt a compara
int functie; //VAL 1 PT PRIMA RULARE SI 2 PT URMATOARELE

char numeDirSafe[50]; //numele dir in care vom izola fis malitioase
char numeDirOutput[50]; //numele dir in care punem snapshoturile

void mutaFisierInFolder(char* absPath , char* numeFis , char* numeDir)
{
  char pathToDir[MAX_PATHL];

  sprintf(pathToDir , "%s/%s" , numeDir , numeFis);

  if (rename(absPath, pathToDir) == 0) 
  {
      //printf("Fisier mutat cu succes.\n");
  } 
  else 
  {
    perror("Eroare la mutarea fisierului ");
  }
}

//functia de salvare a snapshotului pentru un folder(dupa ce a
//fost realizata filtrarea si mutarea fisierelor malitioase,
//testate prin rularea scriptului detectMalware.sh)
void saveFolderStatus(int fd , char* folder)
{
  DIR* dir;
  struct dirent* entry;
  struct stat fileStat;
  int malitios = 0; //flag pt a stii care fis trebuie trecute in snapshot

  if( (dir = opendir(folder)) == NULL)
  {
      perror("Eroare la desch folderului");
      exit(EXIT_FAILURE);
  }
  //parcurgem folderul
  while( (entry = readdir(dir)) != NULL)
  {
    if( (strcmp(entry->d_name , ".") != 0) && (strcmp(entry->d_name , "..") != 0) )
    { // intrari care ne intereseaza
      char absPath[MAX_PATHL];
      sprintf(absPath , "%s/%s" , folder, entry->d_name);
      
      if( (stat(absPath , &fileStat)) == -1)
      {
        perror("Eroare la lstat");
        exit(EXIT_FAILURE);
      }

      //daca fisierul e 'malitios'(are dr 000 nu il punem in snapshot)
      //int acStatus;
      if( access(absPath , R_OK) == -1 && access(absPath , W_OK) == -1 && access(absPath , X_OK) == -1 )//daca toate sunt pe 0 verificam fisierul
      {
        malitios = 0; //flag pt a stii daca trecem sau nu intrarea in snapshot

        printf("NUMELE FISIERELOR FARA DREPTURI: %s\n" , absPath);
        //rulam scriptul pt a verifica continutul fis
        //mai facem un copil sa ruleze doar script
        int pid , status;
        //numele scriptului
        char* pathScript = "/home/dar1u/Desktop/so/so/AplicatieFinalizata/detectMalware.sh";
        //ii dam permisiune de read pt a rula script in fiu
        if (chmod(absPath, S_IRUSR | S_IRGRP | S_IROTH) == 0) 
        {
          //printf("Permisiune de read cu succes.\n");
        } 
        else 
        {
          perror("Eroare la primirea permisiunii de read");
        }
        //vom folosi pipe pt a transmite info de la script
        int pipefd[2];
        char buffer[100];
        //pipefd[0] read
        //pipefd[1] write end
        //cream pipe
        if (pipe(pipefd) == -1) {
          perror("Eroare pipe");
          exit(EXIT_FAILURE);
        }

        pid = fork();

        if(pid < 0)
        {
          perror("Eroare fork");
          exit(EXIT_FAILURE);
        }
        else if(pid == 0) //proces fiu, rulam scriptul
        {
          close(pipefd[0]);//pr fiu scrie
          dup2(pipefd[1], STDOUT_FILENO);//sa scriem pe pipe
         
          execlp("sh" , "sh" , pathScript , absPath , NULL);//rulam scriptul in procesul copil
          
          perror("eroare la execlp");
          exit(EXIT_FAILURE);

        }
        else
        {
          
          close(pipefd[1]);//pr parinte citeste

          ssize_t nbytes = read(pipefd[0] , buffer , sizeof(buffer));

          if (nbytes == -1) {
            perror("read");
            exit(EXIT_FAILURE);
          }

          // Null-terminate the string
          buffer[nbytes] = '\0';

          //printf("Output from the script: %s", buffer);
          
          /// asteptam sa se termine procesul copil
          //apoi ii scoatem dreptul de read inapoi
          wait(&status);

          struct stat file_stat;
          if (stat(absPath, &file_stat) == -1) {
            perror("Error getting file status");
          }

          // Scoatem dreptul de read pt owner, group, and others
          mode_t new_mode = file_stat.st_mode & ~(S_IRUSR | S_IRGRP | S_IROTH);

          //update cu noile permisiuni
          if (chmod(absPath, new_mode) == 0) {
              //printf("Read permission removed successfully.\n");
          } else {
              perror("Error in changing file permissions");                
          }

          
          if (WIFEXITED(status)) 
          {
            //printf("PROCES INCHEIAT NORMAL\n");
            // Procesul copil s-a incheiat normal
            
            if( strcmp(buffer , "SAFE\n") == 0) 
            { malitios = 0;
            //printf("Fisierul %s NU e malitios\n" , absPath);
            }
            
            else //e malitios, trebuie mutat
            {
              malitios = 1;//
              //printf("Fisierul %s e MALITIOS---- ESTE MUTAT\n" , absPath);
              
              mutaFisierInFolder(absPath , entry->d_name , numeDirSafe);
            }
          } 
          else 
          {
            // Child process terminated abnormally
            printf("Child process terminated abnormally\n");
          }
        }
      }
      //gata faza cu filtrarea fisierelor
      
      if(malitios == 0)//e intrare nemalitioasa, o trecem in snapshot
      {
        if (write(fd, absPath , strlen(absPath)) == -1) 
        {
          perror("Eroare la scrierea pathului");
          exit(EXIT_FAILURE);
        }//pt a scrie pathul(nume complet)

        char sizeStr[20];
        char modifTimeStr[20];
        sprintf(sizeStr, "%ld", fileStat.st_size);
        sprintf(modifTimeStr, "%ld", fileStat.st_mtime);

        if (write(fd, " ", 1) == -1 || 
                write(fd, sizeStr, strlen(sizeStr)) == -1 || 
                write(fd, " ", 1) == -1 ||
                write(fd, modifTimeStr, strlen(modifTimeStr)) == -1) 
                {
                  perror("Error writing size or access time");
                  exit(EXIT_FAILURE);
                } //pt a scrie size si last access

        if (write(fd, "\n", 1) == -1)
        {
                  perror("Error writing newline");
                  exit(EXIT_FAILURE);
        }
      }
      //daca entry-ul este de tip director
      if(S_ISDIR(fileStat.st_mode))
        saveFolderStatus(fd , absPath );
    }
  }
  closedir(dir);
  printf("\n-----------Status\nSNAPSHOT for folder %s created successfully\n--------\n" , folder);
}

//functia de comparare a continutului unui folder 
//cu snapshotul salvat al acestuia
void compareFolderToStatus(int fd , int fd2 , char* numeFolder) 
{
  int i = 0;
  char buf[MAX_PATHL*2 + 50];
  ssize_t bytesRead = read(fd , buf , sizeof(buf));

  if(bytesRead == -1)
  {
    perror("Eroare la cit din fd");
    exit(EXIT_FAILURE);
  }

  while(buf[i] != '`')
    i++;
  buf[i] = '\0';
  //printf("%s\n\n\n" , buf);

  char buf2[MAX_PATHL*2 +50];
  bytesRead = read(fd2 , buf2 , sizeof(buf2));

  if(bytesRead == -1)
  {
    perror("Eroare la cit din fd2");
    exit(EXIT_FAILURE);
  }

  i = 0;
  while(buf2[i] != '`')
    i++;
  buf2[i]='\0';
  //printf("%s\n\n\n" , buf2);

  if(strcmp(buf , buf2) != 0)
    printf("\n~~~~SUNT MODIFICARI la fold: ~%s\n~~~~~\n" , numeFolder);
  else
    printf("\n~~~~NU SUNT MODIFICARI la fold: ~%s\n~~~~\n" , numeFolder);
  
}

void scrieTerminatorFisier(int fd)
{
  char c = '`';
  write(fd , &c , 1);
}

//functia principala care salveaza/compara si salveaza snapshotul, 
//folosindu-se de save si compare...
void prelucreazaFoldere(char* numeFolder , int functie)
{
  //sa verificam daca numeFolder e folder
  char numeFisBaza[] = "";
  strcat(numeFisBaza , numeFolder);

  char numeFisStatus[100] = "";
  char numeFisStatus2[100] = "";//pt cele 2 fisiere create pt fiecare

  strcpy(numeFisStatus , numeFisBaza);
  strcpy(numeFisStatus2 , numeFisBaza);
  
 
  //TREBUIE SA FACEM FIS CU NUMELE FOLDERULUI PT A UPDATA DOAR ACEL FIS DACA REAPELAM
  //CU PARAM IN ALTA ORDINE
  char sufix[50] = "1.txt";
  char sufix2[50] = "2.txt";

  strcat(numeFisStatus , sufix);
  strcat(numeFisStatus2 , sufix2);

  char path1[MAX_PATHL];
  char path2[MAX_PATHL];
  //path1 si path2 sunt caile complete spre fisierele de snapshot
  //create in folderul dedicat pt snapshoturi

  sprintf(path1 , "%s/%s" , numeDirOutput , numeFisStatus);
  sprintf(path2 , "%s/%s" , numeDirOutput , numeFisStatus2);

  //printf("%s\t%s\n" , numeFisStatus , numeFisStatus2);
 
  int fd1 , fd2;
  struct stat fileStat;

  if(functie == 1)
  {
    if( (fd1 = open(path1 , O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
    {
      perror("Er la desch fis de statusI ");
    }

    saveFolderStatus(fd1 , numeFolder);
    scrieTerminatorFisier(fd1);

    close(fd1);
  }
  else //a 2+ rulare
  {
    if( (fd1 = open(path1 , O_RDONLY )) == -1)
    {
      perror("Er la desch fis de statusI") ;
      exit(EXIT_FAILURE);
    }

    if( (stat(path2 , &fileStat)) == -1)//fis nu exista
    {
      if( (fd2 = open(path2 , O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)//il cream
      {
        perror("Eroare la desch fisierului de statusF ");
        exit(EXIT_FAILURE);
      }
    }
    else
      if( (fd2 = open(path2 , O_WRONLY | O_TRUNC)) == -1)
      {
        perror("Eroare la desch fisierului de statusF ");
        exit(EXIT_FAILURE);
      }

    saveFolderStatus(fd2 , numeFolder);
    scrieTerminatorFisier(fd2);// salvam statusul actual in fd2
    close(fd2);

    //redesch pt citire
    if( (fd2 = open(path2 , O_RDONLY )) == -1)
    {
      perror("Eroare la desch fisierului de statusF");
      exit(EXIT_FAILURE);
    }

    compareFolderToStatus(fd1 , fd2 , numeFolder);
    close(fd1);
    close(fd2);
  }

  //mutaFisierInFolder(numeFisStatus , numeFisStatus , numeDirOutput);
  //mutaFisierInFolder(numeFisStatus2 , numeFisStatus2 , numeDirOutput);

  strcpy(numeFisStatus , "");
  strcpy(numeFisStatus2 , "");
  strcpy(sufix , "");
  strcpy(sufix2 , "");
}

int verifFolder(char* numeFolder)//pt a filtra din main doar arg care sunt nume de foldere
{
  char absPath[100] = "";
  sprintf(absPath , "./%s" , numeFolder);

  struct stat fileStat;

  if( (stat(absPath , &fileStat)) == -1)
    {
      perror("Eroare: nu exista folderul/fisierul dat ca param");
      exit(EXIT_FAILURE);
    }

  if(S_ISDIR(fileStat.st_mode))
    return 1;//e folder

  return 0;
}

//indici globali la care se afla numele dir safe si numele dir de output
int indDirSafe = -1;
int indDirOutput = -1;
void gasesteDir(char* argv[] , int nr)
{
  int i;
  for(i = 1 ; i<=nr ; i++)
  {
    if( strcmp(argv[i] , "-s") == 0 )//gasit flag
    {
      indDirSafe = i + 1;
    }
    if( strcmp(argv[i] , "-o") == 0)
    {
      indDirOutput = i + 1;
    }
  }
}

//In main preluam numele folderelor si flagurile ca arg in linie de comanda
//validam toate argumentele si afisam erori in lipsa lor
//Userul citeste de la tastatura functia(1 daca ruleaza prima data),
//                                     (2 daca ruleaza a 2+ oara)
int main(int argc , char* argv[])
{
  if(argc < 2)
  {
    perror("Dati argument numele folderului\n");
    exit(EXIT_FAILURE);
  }

 
  int nrFoldere = argc - 1;
  int i , functie;
  int pid;

  gasesteDir(argv , nrFoldere);
  //printf("%d\n" , indDirSafe);
  //printf("%d\n" , indDirOutput);

  if(indDirSafe < 0)
  {
    perror("Nu ati introdus flagul -s si directorul in care se vor muta fisierele mal");
    exit(EXIT_FAILURE);
  }

  if(indDirOutput < 0)
  {
    perror("Nu ati introdus flagul -o si directorul in care se stocheaza snapshoturile");
    exit(EXIT_FAILURE);
  }

  if( verifFolder(argv[indDirSafe]) == 0) //nu e folder 
    perror("Argumentul dat dupa flagul -s nu este folder sau nu exista");
  
  strcpy(numeDirSafe , argv[indDirSafe]);//var in care pastram numele dir safe

  if( verifFolder(argv[indDirOutput]) == 0) //nu e folder 
    perror("Argumentul dat dupa flagul -o nu este folder sau nu exista");
  
  strcpy(numeDirOutput , argv[indDirOutput]);//var in care pastram numele dir out

  
  printf("Introduceti 1 daca e prima rulare, 2 in caz contrar\n");
  scanf("%d" , &functie);


  for(i = 1; (i<=nrFoldere) ; i++)//sa nu apelam snapshotul pe flag si dir in care vom muta
  {
    //printf("%d\n" , i);
    if(i != indDirSafe && i != indDirSafe -1 && i != indDirOutput && i != indDirOutput -1)
    {
      //verif daca fiecare arg e folder
      if( verifFolder(argv[i]))//e folder, facem ce ne cere
      {
        pid = fork();
        if(pid < 0)
        {
          perror("Eroare fork");
          exit(EXIT_FAILURE);
        }
        else if(pid == 0)//e un copil
        {
          prelucreazaFoldere(argv[i] , functie);//functia principala
          //in care se apeleaza si functia de salvare si cea de comparare
          exit(0);
        }
      }
    }
  }

  int statusWait;

  for(i=1 ; i<=nrFoldere - 4; i++)//
  {
    pid = wait(&statusWait);
    if(pid == -1)
    {
      perror("Eroare la wait");
      exit(EXIT_FAILURE);
    }

    if(WIFEXITED(statusWait))
    {// proces copil incheiat normal
      int exit_code = WEXITSTATUS(statusWait);
      printf("\n-------PROCES\nChild process %d with PID %d exited with code: %d\n--------\n", i , pid , exit_code);
    }
    else
      printf("Proces copil incheiat anormal\n");
  }
    
  
  return 0;
}