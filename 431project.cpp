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

#include "431project.h"

std::pair<double, double> GLOB_baseline_EP_pair;
std::map<std::string, std::map<std::string, double>* > GLOB_extracted_values;
std::map<std::string, std::pair<double, double> > GLOB_derived_values;
std::map<std::string, unsigned int> GLOB_seen_configurations;


void initbaseline(std::string configuration){
  GLOB_baseline_EP_pair.first=calculategeomeanEDP(configuration);
  GLOB_baseline_EP_pair.second=calculategeomeanExecutionTime(configuration)*calculategeomeanEDP(configuration);
}


int main(int argc, char** argv){
  std::ofstream logfile;
  std::ofstream bestfile;
  std::string bestTimeconfig=GLOB_baseline;
  std::string bestEDPconfig=GLOB_baseline;
  std::string currentConfiguration=GLOB_baseline;
  int optimizeforEDP=0;
  int optimizeforEXEC=0;
  srand(0); // for stability during testing

  if(2!=argc){
    fprintf(stderr,"Wrong number of arguments! Run as DSE e or DSE p for energy or performance run, respectively\n");
    return -1;
  } else { 
    int isEarg=('e'==argv[1][0]);
    int isParg=('p'==argv[1][0]);
    if(!(isEarg||isParg)){
      fprintf(stderr,"Invalid argument! Run as \"DSE e\" or \"DSE p\" for efficiency or performance optimization run, respectively\n");
      return -1;
    } else {
      system("mkdir -p logs");
      system("mkdir -p summaryfiles");
      system("mkdir -p rawProjectOutputData");
      if(isParg){// do performance exploration
        optimizeforEXEC=1;
        logfile.open("logs/PerformanceOptimized-minED2P.log");
        bestfile.open("logs/PerformanceOptimized-minED2P.best");
      } else{ // do energy-efficiency exploration
        optimizeforEDP=1;
        logfile.open("logs/EfficiencyOptimized-minEDP.log");
        bestfile.open("logs/EfficiencyOptimized-minEDP.best");
      }
    }
  }
  runexperiments(GLOB_baseline,0,0); // generate baseline values
  populate(GLOB_baseline); // read raw values from files
  initbaseline(GLOB_baseline); // special-case handling for baseline
  
  logfile << calculategeomeanEDP(currentConfiguration)/GLOB_baseline_EP_pair.first << "," 
          << calculategeomeanExecutionTime(currentConfiguration)*calculategeomeanEDP(currentConfiguration)/GLOB_baseline_EP_pair.second << ","
          << calculategeomeanEDP(currentConfiguration) << "," 
          << calculategeomeanExecutionTime(currentConfiguration)*calculategeomeanEDP(currentConfiguration) << std::endl;

  std::cout <<std::endl; //clean up line breaks for baseline
  
  // do extremely simplistic approximation of simulated annealing
  for(unsigned int round =1; round < 51; ++round){
    double threshold=pow(2.71,((-1.0)*(1+(round)/5.0)));
    for(unsigned int iteration=1; iteration < 21; ++iteration){
      double randDbl=((double)(rand()))/((double)(RAND_MAX));
      std::string nextconf=generateNextConfigurationProposal(currentConfiguration,bestTimeconfig,bestEDPconfig,optimizeforEXEC,optimizeforEDP);
      runexperiments(nextconf,round,iteration);
      populate(nextconf);
      if (0==(*(GLOB_extracted_values[nextconf]))[GLOB_prefixes[0]+GLOB_fields[0]]){ // quick and dirty sanity check
        // run failed, try another, don't count this one
        std::cout<<"R";
        --iteration; continue;
      }
      double proposedGEOEDP=calculategeomeanEDP(nextconf);
      double bestEDP=calculategeomeanEDP(bestEDPconfig);;
      double proposedGEOEXEC=calculategeomeanExecutionTime(nextconf)*calculategeomeanEDP(nextconf);
      double bestExec=calculategeomeanExecutionTime(bestTimeconfig)*calculategeomeanEDP(bestTimeconfig);
      if (proposedGEOEDP < bestEDP){ // new best EDP
        bestEDPconfig=nextconf;
      }
      if (proposedGEOEXEC < bestExec){ // new best EXEC
        bestTimeconfig=nextconf;
      }
      if(optimizeforEXEC){ // if optimizing for EXEC
        if(proposedGEOEXEC < bestExec){ // if better, always accept
          currentConfiguration=nextconf;
        } else if(randDbl<threshold){ // else accept with probability threshold
          currentConfiguration=nextconf;          
        }
      } else { // optimizing for EDP
        if(proposedGEOEDP < bestEDP){ // if better, always accept
          currentConfiguration=nextconf;
        } else if(randDbl<threshold){ // else accept with probability threshold
          currentConfiguration=nextconf;
        }        
      }
      
      logfile << calculategeomeanEDP(currentConfiguration)/GLOB_baseline_EP_pair.first << "," 
              << calculategeomeanExecutionTime(currentConfiguration)*calculategeomeanEDP(currentConfiguration)/GLOB_baseline_EP_pair.second << ","
              << calculategeomeanEDP(currentConfiguration) << "," 
              << calculategeomeanExecutionTime(currentConfiguration)*calculategeomeanEDP(currentConfiguration) << std::endl;
       }
    std::cout << std::endl;
  }
  // all done

  //dump best configuration and associated data

  bestfile << bestEDPconfig << ","
           << calculategeomeanEDP(bestEDPconfig)/GLOB_baseline_EP_pair.first << "," 
           << calculategeomeanExecutionTime(bestEDPconfig)*calculategeomeanEDP(bestEDPconfig)/GLOB_baseline_EP_pair.second << ","
           << calculategeomeanEDP(bestEDPconfig) << "," 
           << calculategeomeanExecutionTime(bestEDPconfig)*calculategeomeanEDP(bestEDPconfig) <<",";
  for (int i=0; i<5; ++i){
    bestfile << calculateEDP(bestEDPconfig,GLOB_prefixes[i]) << ","
             << calculateEDP(bestEDPconfig,GLOB_prefixes[i])/calculateEDP(GLOB_baseline,GLOB_prefixes[i]) << ",";
  }
  bestfile << std::endl;
  bestfile << bestTimeconfig << ","
           << calculategeomeanEDP(bestTimeconfig)/GLOB_baseline_EP_pair.first << "," 
           << calculategeomeanExecutionTime(bestTimeconfig)*calculategeomeanEDP(bestTimeconfig)/GLOB_baseline_EP_pair.second << ","
           << calculategeomeanEDP(bestTimeconfig) << "," 
           << calculategeomeanExecutionTime(bestTimeconfig)*calculategeomeanEDP(bestTimeconfig) << "," ;
  for (int i=0; i<5; ++i){
    bestfile << calculateExecutionTime(bestTimeconfig,GLOB_prefixes[i])*calculateEDP(bestTimeconfig,GLOB_prefixes[i]) << ","
             << calculateExecutionTime(bestTimeconfig,GLOB_prefixes[i])*calculateEDP(bestTimeconfig,GLOB_prefixes[i])/(calculateExecutionTime(GLOB_baseline,GLOB_prefixes[i])*calculateEDP(GLOB_baseline,GLOB_prefixes[i]) )<< ",";
  }
  bestfile << std::endl;
  
  logfile.close();
  bestfile.close();
}
