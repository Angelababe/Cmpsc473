#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <math.h>
#include <fcntl.h>
#include <sys/file.h>

#include "431project.h"


/*
Runs experiments for a given configuration, if they have not already been run. Stores raw data in globally accessible location
*/
int runexperiments(std::string configuration, unsigned int round, unsigned int iteration){
  struct stat buffer;
  std::string dotconfig = configuration; // filename version
  std::replace(dotconfig.begin(),dotconfig.end(),' ','.'); // generate filename version
  std::string startfile = GLOB_outputpath+"LOCK."+dotconfig+".LOCK"; // lock file
  std::string endfile = GLOB_outputpath+"DONE."+dotconfig+".DONE"; // post-run file
  if(!isan18dimconfiguration(configuration)){ // Configuration in incorrect format!!!
    std::cerr << "ATTEMPTING TO RUN INCORRECTLY FORMATTED CONFIGURATION!\nABORTING EXECUTION IMMEDIATELY!\nConfiguration in question: " << configuration <<std::endl;
    exit(-1);
  }
  if(0==(stat(endfile.c_str(), &buffer))){ // already generated for this configuration
    std::cout << round << "." << iteration <<"." <<"f"<<std::endl;
    return 0;
  } else {
    if(0==(stat(startfile.c_str(), &buffer))){
      ; // do not create file - lock file exists
    } else {
      // create lock file if it doesn't already exist
      std::string cmdstr="touch "+ startfile + "; chmod a+rwx "+ startfile;
      system(cmdstr.c_str()); // this races, but all races should result in equivalent end state
    }
    // lock file has now been created - not yet locked
    
    /* REMOVED
     * Locking schema did not work on instructional machines
     *
     
    // lock the lock file    
    int fd;
    if(-1==(fd = open(startfile.c_str(),O_RDWR))){
      perror("File system error on OPEN. Could not open lock file. Quitting.\n");
      exit(-1);
    }

    // fd is now a valid file descriptor for the lock file
    if(-1==(flock(fd,LOCK_EX))){
      perror("FLOCK failed! Quitting.\n");
      exit(1);
    }
   
    // lock file locked

    */


    // recheck for DONE file (someone else may have had the lock before you did)
    if(0==(stat(endfile.c_str(), &buffer))){ // already generated for this configuration during your attempt to aquire lock
      std::cout << round << "." << iteration <<"." <<"cf"<<std::endl;
      return 0;
    } else { 
      // run experiments;
      std::string bashcmdline = GLOB_script + configuration + " >/dev/null";
      std::cout << round << "." << iteration <<"." <<"g"<<std::endl;
      int retval= system(bashcmdline.c_str());


      /* REMOVED
      // unlock lock file
      if (-1==flock(fd,LOCK_UN)) {
        perror("FLOCK failed to unlock! Quitting.\n");
        exit(1);
      }
      */
      return retval;
    }
  }
}

/*
 * Retrieves data from raw result files and places it in an in-memory data structure
 */
void populate(std::string configuration){
  std::map<std::string, double>* curmap = GLOB_extracted_values[configuration];
  if(!curmap){
    curmap=new std::map<std::string,double>;
    GLOB_extracted_values[configuration]=curmap;
  }
  std::string cmdtail=" | sed -re 's:[ ]+: :g' | cut -d\\  -f2 >";
  std::string cmdhead="grep ";
  std::string dotconfig=configuration;
  std::replace(dotconfig.begin(),dotconfig.end(),' ','.'); // generate filename version
  dotconfig+=".simout";
  for (int i=0; i<5; ++i){ // for each benchmark
    std::string querybody=GLOB_outputpath + GLOB_prefixes[i] + dotconfig + cmdtail + "summaryfiles/"+ GLOB_prefixes[i] + dotconfig + ".summary";
    std::string curquery=cmdhead + "sim_num_insn " + querybody;
    system(curquery.c_str());
    // switch to append
    querybody=GLOB_outputpath + GLOB_prefixes[i] + dotconfig + cmdtail + "> summaryfiles/"+ GLOB_prefixes[i] + dotconfig + ".summary";
    for (int j=1;j<7;++j){ //skip first field
      curquery=cmdhead + GLOB_fields[j] + querybody;
      system(curquery.c_str());
    }
    
    // summary file generated, retrieve values
    // !does not perform error checking!
    
    std::fstream summaryfile(("summaryfiles/"+GLOB_prefixes[i]+dotconfig+".summary").c_str(), std::ios_base::in);
    for(int j=0;j<7;++j){
      double curval;
      summaryfile>>curval;
      (*curmap)[GLOB_prefixes[i]+GLOB_fields[j]]=curval;
    }
  }
  GLOB_seen_configurations[configuration]=1;
}

//Geomean of execution times across benchmarks in a configuration
double calculategeomeanExecutionTime(std::string configuration){
  double geomean=1.0;
  for (int i =0; i<5; ++i){
    geomean*=calculateExecutionTime(configuration, GLOB_prefixes[i]);
  }
  geomean=pow(geomean,1.0/5.0);
  return geomean;
}

//Geomean of EDP across benchmarks in a configuration
double calculategeomeanEDP(std::string configuration){
  double geomean=1.0;
  for (int i =0; i<5; ++i){
    geomean*=calculateEDP(configuration, GLOB_prefixes[i]);
  }
  geomean=pow(geomean,1.0/5.0);
  return geomean;
}
 

// Trivial sanity check
int isan18dimconfiguration(std::string configuration){
  if(35!=configuration.size()){
    std::cerr << " Wrong length for configuration\n"; 
    return 0; // wrong length
  }
  for(int fieldnum =0; fieldnum <18; ++fieldnum){
    int j = 2*fieldnum;
    std::string field = configuration.substr(j,1);
    if ("0"==field||"1"==field||"2"==field||"3"==field||"4"==field||"5"==field||"6"==field||"7"==field||"8"==field||"9"==field){
      // is a digit - convert to unteger value
      int fieldvalue=atoi(field.c_str());
      if (fieldvalue>=GLOB_dimensioncardinality[fieldnum]){
        std::cerr << "Field out of range: " << fieldnum << " " << fieldvalue <<std::endl; 
        return 0; // dimension value out of range
      }
    } else {
      std::cerr << "Field not a digit: " << fieldnum <<std::endl; 
      return 0; // field not a digit
    }
    if(17!=fieldnum && " "!=configuration.substr(j+1,1)){
      std::cerr << "Odd characters not spaces for field: " << fieldnum <<std::endl; 
      return 0; // not single digits separated by spaces
    }
  }
  return 1; //Passed tests
}

void extractConfiguration(std::string configuration, int* buffer18){
  if(!isan18dimconfiguration(configuration)){
    std::cerr << "Invalid configuration passed to extractConfiguration. Exiting.\n"; 
    exit(-1);
  } else {
    for(int fieldnum =0; fieldnum <18; ++fieldnum){
      int j = 2*fieldnum;
      std::string field = configuration.substr(j,1);
      buffer18[fieldnum]=atoi(field.c_str());
    }
  }
}


double cycleTime(std::string configuration){
  bool inorder = (0==atoi((configuration.substr(4,1)).c_str()));
  int width = 1 << atoi((configuration.substr(0,1)).c_str());
  if (inorder){
    switch(width){
    case 1:return 100e-12;
    case 2:return 120e-12;
    case 4:return 140e-12;
    case 8:return 165e-12;
    }
  }else{
    switch(width){
    case 1:return 115e-12;
    case 2:return 125e-12;
    case 4:return 150e-12;
    case 8:return 175e-12;
    }
  }
  std::cerr <<"invalid width or inorder setting"<<std::endl;
  exit(-1); // invalid width/inorder
  return 1e-12; // should never get here
}


double EPCI(std::string configuration){
  bool inorder = (0==atoi((configuration.substr(4,1)).c_str()));
  int width = 1 << atoi((configuration.substr(0,1)).c_str());
  if (inorder){
    switch(width){
    case 1:return 8e-12;
    case 2:return 10e-12;
    case 4:return 14e-12;
    case 8:return 20e-12;
    }
  }else{
    switch(width){
    case 1:return 10e-12;
    case 2:return 12e-12;
    case 4:return 18e-12;
    case 8:return 27e-12;
    }
  }
  std::cerr <<"invalid width or inorder setting"<<std::endl;
  exit(-1); // invalid width/inorder
  return 1e-12; // should never get here
}


double PipelineLeakage(std::string configuration){
  bool inorder = (0==atoi((configuration.substr(4,1)).c_str()));
  int width = 1 << atoi((configuration.substr(0,1)).c_str());
  if (inorder){
    switch(width){
    case 1:return 1e-3;
    case 2:return 1.5e-3;
    case 4:return 7e-3;
    case 8:return 30e-3;
    }
  }else{
    switch(width){
    case 1:return 1.5e-3;
    case 2:return 2e-3;
    case 4:return 8e-3;
    case 8:return 32e-3;
    }
  }
  std::cerr <<"invalid width or inorder setting"<<std::endl;
  exit(-1); // invalid width/inorder
  return 1e-12; // should never get here
}

// leakage in watts
double getcacheleak(unsigned int size){
  if (size <=8192){
    return 125e-6;
  } else if (size<=16384){
    return 250e-6;
  } else if(size<=32768){
    return 500e-6;
  } else if(size<=65536){
    return 1e-3;
  } else if(size<=131072){
    return 2e-3;
  } else if(size<=262144){
    return 4e-3;
  } else if(size<=524288){
    return 8e-3;
  } else if(size<=1048576){
    return 16e-3;
  } else if(size<=2097152){
    return 32e-3;
  }
 
  //  std::cerr << "USED BAD CACHE SIZE: "<< size <<std::endl;
  return 40e-3;
}

// all sizes in bytes
unsigned int getdl1size(std::string configuration){
  unsigned int dl1sets = 32 << atoi((configuration.substr(2*6,1)).c_str());
  unsigned int dl1assoc = 1 << atoi((configuration.substr(2*7,1)).c_str());
  unsigned int dl1blocksize = 8 * (1 << (atoi((configuration.substr(0,1)).c_str())));
  return dl1assoc*dl1sets*dl1blocksize;
}

unsigned int getil1size(std::string configuration){
  unsigned int il1sets = 32 << atoi((configuration.substr(2*8,1)).c_str());
  unsigned int il1assoc = 1 << atoi((configuration.substr(2*9,1)).c_str());
  unsigned int il1blocksize = 8 * (1 <<(atoi((configuration.substr(0,1)).c_str())));
  return il1assoc*il1sets*il1blocksize;
}

unsigned int getl2size(std::string configuration){
  unsigned int l2sets = 256 << atoi((configuration.substr(2*10,1)).c_str());
  unsigned int l2blocksize =  16 << (atoi((configuration.substr(2*11,1)).c_str()));
  unsigned int l2assoc = 1 << atoi((configuration.substr(2*12,1)).c_str());
  return l2assoc*l2sets*l2blocksize;
}

// leakage in watts
double cacheleak(std::string configuration){
  double sum=0;
  sum+=getcacheleak(getdl1size(configuration));
  sum+=getcacheleak(getil1size(configuration));
  sum+=getcacheleak(getl2size(configuration));
  return sum;
}

//energy per access in joules
double getaccessenergy(unsigned int size){
  if (size <=8192){
    return 20e-12;
  } else if (size<=16384){
    return 28e-12;
  } else if(size<=32768){
    return 40e-12;
  } else if(size<=65536){
    return 56e-12;
  } else if(size<=131072){
    return 80e-12;
  } else if(size<=262144){
    return 112e-12;
  } else if(size<=524288){
    return 160e-12;
  } else if(size<=1048576){
    return 224e-12;
  } else if(size<=2097152){
    return 360e-12;
  }
  
  //  std::cerr << "USED BAD CACHE SIZE: "<< cachesize <<std::endl;
  return 400-12;
}

/*
 * Use data in GLOB_extracted_values to calculate execution time, in seconds, of 1 benchmark, on one configuration
 */
double calculateExecutionTime(std::string configuration, std::string benchmarkprefix){
  double secondspercycle=cycleTime(configuration);
  double cycleCount=  (*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[1]]; // field 1 is sim_cycle
  return secondspercycle*cycleCount;
}

/*
 * Use data in GLOB_extracted_values to calculate energy delay product, in Joule-seconds, of 1 benchmark, on one configuration. EDP will = Time in seconds * ((sum of all leakage in W) * Time in seconds) + (sum over all energy contributions)
 */
double calculateEDP(std::string configuration, std::string benchmarkprefix){
  //recall that GLOB_fields[7]={"sim_num_insn ", "sim_cycle ","il1.accesses ","dl1.accesses ","ul2.accesses ","ul2.misses ","ul2.writebacks "};
  double executiontime=calculateExecutionTime(configuration, benchmarkprefix);
  double leakageEnergy=executiontime * (PipelineLeakage(configuration)+cacheleak(configuration)+/*Main memory refresh*/512e-3);
  double executionEnergy=EPCI(configuration)*(*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[0]];
  double instaccessEnergy=getaccessenergy(getil1size(configuration)) * (*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[2]];
  double d1accessEnergy=getaccessenergy(getdl1size(configuration)) * (*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[3]];
  double l2accessEnergy=getaccessenergy(getl2size(configuration)) * (*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[4]];
  double memoryaccessEnergy=2e-9*1 * (((*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[5]]) + (*(GLOB_extracted_values[configuration]))[benchmarkprefix+GLOB_fields[6]]);
  executionEnergy=executionEnergy+instaccessEnergy+d1accessEnergy+l2accessEnergy+memoryaccessEnergy;
  return executiontime * (leakageEnergy+executionEnergy); 
}

/*
 * Given the current best known configuration, the current configuration, and the globally visible map of all previously investigated configurations, suggest a previously unexplored design point. You will only be allowed to investigate 1000 design points in a particular run, so choose wisely.
 */
std::string generateNextConfigurationProposal(std::string currentconfiguration, std::string bestEXECconfiguration, std::string bestEDPconfiguration, int optimizeforEXEC, int optimizeforEDP){
  std::string nextconfiguration=GLOB_baseline;
  while(GLOB_seen_configurations[nextconfiguration]){ // check if proposed configuration has been seen before; if so, ask again
    do {
      nextconfiguration=YourProposalFunction(currentconfiguration, bestEXECconfiguration, bestEDPconfiguration, optimizeforEXEC, optimizeforEDP);
    } while (!validateConfiguration(nextconfiguration)); // if proposal is invalid, ask again; eases implentation of random search
  }
  return nextconfiguration;
}

