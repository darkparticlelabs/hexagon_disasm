#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include "elf.h"
#include "disasm_hexagon.h"

void read_ELF_file_header(FILE* fp,Elf32_Ehdr *filehdr)
{
	
	//rewind(fp);	
	fread(filehdr,sizeof(Elf32_Ehdr),1,fp);
}
int is_ELF(Elf32_Ehdr *hdr)
{
	char str[16]="";
	memcpy_s(str,16,hdr->e_ident,16);
	if(strncmp(str,"\177ELF",4)==0)
		return 1;
	else
		return -1;

}
int read_ELF_program_header(int sect_num,Elf32_Phdr *prg_hdr,FILE *fp)
{
	int numsect;
	Elf32_Ehdr elfhdr;
	off_t prg_hdr_off;
	fseek(fp,(off_t)0,SEEK_SET);
	read_ELF_file_header(fp,&elfhdr);
	numsect=elfhdr.e_shnum;
	if((numsect<sect_num)||(sect_num<0))
		return -1;
	prg_hdr_off=elfhdr.e_phoff;
	prg_hdr_off+=elfhdr.e_phentsize*sect_num;
	fseek(fp,(off_t)prg_hdr_off,SEEK_SET);
	fread(prg_hdr,sizeof(Elf32_Phdr),1,fp);
	return 1;
}
int GetFileBlob(FILE * file,int offset,int length,uint8_t** blob)
{
	*blob = new uint8_t[length];
	long int curPos = ftell(file);
	fseek(file,offset,SEEK_SET);
	fread(*blob,length,1,file);
	//rewind(fp);
	fseek(file,curPos,SEEK_SET);
	return 0;
}
void process_prg_hdr(FILE * file,Elf32_Phdr *prg_hdr,FILE* log)
{
	uint8_t* data = NULL;
	printf("Type ");
	//offset of file is located here under prg_hdr->p_offset
	switch(prg_hdr->p_type)
	{
		case 0:	printf("NULL==UNUSED ");
			break;
		case 1:	printf("LOAD==LOADABLE \n");
			printf("Disassembling offset: 0x%p length: 0x%x\n",prg_hdr->p_offset,prg_hdr->p_filesz);
			GetFileBlob(file,prg_hdr->p_offset,prg_hdr->p_filesz,&data);
			Disassemble(data,prg_hdr->p_filesz,log);
			delete[prg_hdr->p_filesz] data;
			break;
		case 2: printf("DYNAMIC==DYNAMIC LINK INFO");
			break;
		case 3: printf("INTRP==Program interpreter");
			break;
		case 4: printf("AUX==Auxiliary info");
			break;
		case 5: printf("SHLIB== reserved");
			break;
		case 6: printf("PHDR == entry for header table itself");
			break;
		case 7: printf("TLS==thread local storage");
			break;
		case 8: printf("NUM== number of defined types");
			break;
		case 0x60000000: printf("LOOS== start of os specific");
			break;
		case 0x6474e550: printf("GCC_EH_FRAME header");
			break;
		case 0x6474e551: printf("STACK executability");
			break;
		case 0x6474e552: printf("READ_ONLY after RELOC");
			break;
		case 0x6ffffffa: printf("LOSUNW / SUNWBSS sun specific");
			break;
		case 0x6ffffffb: printf("SUNWSTACK sunspecific stack");
			break;
		case 0x6fffffff: printf("OS SPECIFIC ends");
			break;
		case 0x70000000: printf("START of Processor Specific");
			break;
		case 0x7fffffff: printf("END processor specific");
			break;
	}
	printf("\n");
}
int read_ELF_section_header(int sect_num,Elf32_Shdr *sect_hdr,FILE *fp)
{
	int numsect;
	Elf32_Ehdr elfhdr;
	off_t sect_hdr_off;
	fseek(fp,(off_t)0,SEEK_SET);
	read_ELF_file_header(fp,&elfhdr);	
	numsect=elfhdr.e_shnum;
	if ((numsect<sect_num)||(sect_num<0))
		return -1;
	sect_hdr_off=elfhdr.e_shoff;
	//rewind(fp);
	sect_hdr_off+=elfhdr.e_shentsize*sect_num;
	fseek(fp,(off_t)sect_hdr_off,SEEK_SET);
	fread(sect_hdr,sizeof(Elf32_Shdr),1,fp);
	return 1;	
}
void display_proghdr(FILE *fp,FILE* log)
{
	Elf32_Ehdr ehdr;
	Elf32_Phdr* phdr = new Elf32_Phdr();
	int num_hdrs,i;
	char *buff=NULL;
	fseek(fp,(off_t)0,SEEK_SET);
	read_ELF_file_header(fp, &ehdr);
	if(is_ELF(&ehdr)==-1)
	{
		printf("Not an ELF file\n");
		exit(0);
	}
	num_hdrs=ehdr.e_phnum;
	buff=(char*)malloc(phdr->p_filesz);
	if (!buff)
	{
		printf("Malloc failed to allocate buffer prog header\n");
		exit(0);
	}
	fseek(fp,(off_t)phdr->p_offset,SEEK_SET);
	fread(buff,phdr->p_filesz,1,fp);
	printf("There are [%d] prog headers\n",num_hdrs);
	printf("Program header details\n=======================\n");
	for(i=0;i<num_hdrs;i++)
	{
		if(read_ELF_program_header(i,phdr,fp)==-1)
		{
			printf("Wrong header to read\n");
		}
		else
		{
			printf("[p-header %3d] \t",i);
			process_prg_hdr(fp,phdr,log);
			
		}
	}
	if(buff)
		free(buff);
}
void process_sect_hdr(Elf32_Shdr *sect_hdr,char *sect_name_buff)
{
	int idx;
	idx=sect_hdr->sh_name;
	printf(" %-20s ",sect_name_buff+idx);
	if(sect_hdr->sh_entsize)
		printf(" %c ",'*');
	else
		printf(" %c ",' ');
	switch(sect_hdr->sh_type)
	{	
		case 0: printf("NULL           \t");
			break;
		case 1: printf("PROGBITS       \t");
			break;
		case 2: printf("SYMTAB         \t");
			break;
		case 3: printf("STRTAB         \t");
			break;
		case 4: printf("RELOC ADN      \t");
			break;
		case 5: printf("HASH           \t");
			break;
		case 6: printf("DYNAMIC         \t");
			break;
		case 7: printf("NOTE           \t");
			break;
		case 8: printf("NOBIT          \t");
			break;
		case 9: printf("RELOC          \t");
			break;
		case 10: printf("*reserved*     \t");
			break;
		case 11: printf("DYNSYM         \t");
			break;
		case 14: printf("INITARR        \t");
			break;
		case 15: printf("FINIARR        \t");
			break;
		case 16: printf("PREINIT        \t");
			break;
		case 17: printf("SECTGRP        \t");
			break;
		case 18: printf("EXT-SHNDX      \t");
			break;
		case 19: printf("NUM-DEF-TYP    \t");
			break;
		case 0x60000000: printf("OS SPECIFIC    \t");
			break;
		case 0x6ffffff5: printf("GNU_ATTR       \t");
			break;
		case 0x6ffffff6: printf("GNU_HASH       \t");
			break;
		case 0x6ffffff7: printf("PRELNKLIBLST   \t");
			break;
		case 0x6ffffff8: printf("CKSUM          \t");
			break;
		case 0x6ffffffa: printf("SUN SPECIFIC   \t");
			break;			
		case 0x6ffffffb: printf("SUNCOMDAT      \t");
			break;
		case 0x6ffffffc: printf("SUNSYMINFO     \t");
			break;
		case 0x6ffffffd: printf("GNUVERDEF      \t");
			break;
		case 0x6ffffffe: printf("GNUVERNEED     \t");
			break;
		case 0x6fffffff: printf("GNUVERSYM      \t");
			break;
		case 0x70000000: printf("LOPROC         \t");
			break;
		case 0x7fffffff: printf("HIPROC         \t");
			break;
		case 0x80000000: printf("APP beg        \t");
			break;
		case 0x8fffffff: printf("APP end        \t");
			break;
	}
	printf("linked to %3d sect\n",sect_hdr->sh_link);
}
void display_sections(FILE *fp)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr sec_hdr;
	int num_hdrs,i;
	char *buff=NULL;	
	fseek(fp,(off_t)0,SEEK_SET);
	read_ELF_file_header(fp, &ehdr);
	if(is_ELF(&ehdr)==-1)
	{
		printf("Not an ELF file\n");
		exit(0);
	}
	num_hdrs=ehdr.e_shnum;
	if(read_ELF_section_header(ehdr.e_shstrndx,&sec_hdr,fp)==-1)
	{
		printf("Error: reading section string table sect_num= %d\n",ehdr.e_shstrndx);
		exit(0);
	}
	//we read the shstrtab
	// read content from the file
	buff=(char*)malloc(sec_hdr.sh_size);
	if (!buff)
	{
		printf("Malloc failed to allocate buffer for shstrtab\n");
		exit(0);
	}
	//seek to the offset in the file,
	fseek(fp,(off_t)sec_hdr.sh_offset,SEEK_SET);
	fread(buff,sec_hdr.sh_size,1,fp);
	printf("There are [%d] sections\n",num_hdrs);	
	for(i=0;i<num_hdrs;i++)
	{
		if(read_ELF_section_header(i,&sec_hdr,fp)==-1)
		{
			printf("Wrong Section to read\n");
		}
		else
		{
			printf("[section %3d] ",i);
			process_sect_hdr(&sec_hdr,buff);
			
		}
	}
	if(buff)
		free(buff);
}
int process_symtab(int sect_num,FILE *fp)
{
	Elf32_Shdr sect_hdr;	
	Elf32_Sym mysym;
	char *name_buf=NULL;
	int num_sym,link,i,idx;
	off_t sym_data_offset;
	int sym_data_size;
	if(read_ELF_section_header(sect_num,&sect_hdr,fp)==-1)
	{
		return -1;
	}
	//we have to check to which strtab it is linked
	link=sect_hdr.sh_link;
	sym_data_offset=sect_hdr.sh_offset;
	sym_data_size=sect_hdr.sh_size;
	num_sym=sym_data_size/sizeof(Elf32_Sym);	
	
	//read the coresponding strtab
	if(read_ELF_section_header(link,&sect_hdr,fp)==-1)
	{
		return -1;
	}
	//get the size of strtab in file and allocate a buffer 
	name_buf=(char*)malloc(sect_hdr.sh_size);
	if(!name_buf)
		return -1;
	//get the offset of strtab in file and seek to it
	fseek(fp,sect_hdr.sh_offset,SEEK_SET);
	//read all data from the section to the buffer.
	fread(name_buf,sect_hdr.sh_size,1,fp);	
	//so we have the namebuf now seek to symtab data
	fseek(fp,sym_data_offset,SEEK_SET);
	printf("[%d] symbols\n",num_sym);
	for(i=0;i<num_sym;i++)
	{
				
		//memcpy((char *)&mysym,(char *)sym_buf,sizeof(Elf32_Sym));
		fread(&mysym,sizeof(Elf32_Sym),1,fp);
		//dump_sym(&mysym);
		idx=mysym.st_name;
		//printf("symbol %d index in strtab %d\n",i,idx);		
		printf("[%3d] %s ",i,name_buf+idx);
		switch(ELF32_ST_BIND(mysym.st_info))
		{
			case 0: printf(" LOCAL ");
				break;
			case 1: printf(" GLOBAL ");
				break;
			case 2: printf(" WEAK ");
				break;
			case 3: printf(" NUM ");
				break;
			case 10: printf(" OS-specific-start ");
				break;
			case 12: printf(" OS-specific-end ");
				break;
			case 13: printf(" CPU-specific-start ");
				break;
			case 15: printf("CPU-specific-end ");
				break;
		}
			
			
		switch(ELF32_ST_TYPE(mysym.st_info))
		{
			case 0: printf(" NOTYPE ");
				break;
			case 1: printf(" OBJECT ");
				break;
			case 2: printf(" FUNC ");
				break;
			case 3: printf(" SECTION ");
				break;
			case 4: printf(" FILE ");
				break;
			case 5: printf(" COMMON ");
				break;
			case 6: printf(" TLS ");
				break;
			case 7: printf(" NUM ");
				break;
			case 10: printf(" OS-specific-start ");
				break;
				break;
			case 12: printf(" OS-specific-end ");
				break;
			case 13: printf(" CPU-specific-start ");
				break;
				break;
			case 15: printf(" CPU-specific-end ");
				break;
		}
		switch(mysym.st_shndx)
		{
			case SHN_UNDEF: printf(" UNDEF ");
				break;
			case SHN_LOPROC: printf(" CPU-specific-start ");
				break;
			case SHN_HIPROC: printf(" CPU-specific-end ");
				break;
			case SHN_LOOS: printf(" OS-specific-start ");
				break;
			case SHN_HIOS: printf(" OS-specific-end ");
				break;
			case SHN_ABS: printf(" ABSOLUTE ");
				break;
			case SHN_COMMON: printf(" COMMON ");
				break;
			case SHN_XINDEX: printf(" XINDEX ");
				break;
			
		}		
		printf("\n");
				
	}
	if(name_buf)
		free(name_buf);
	
}
void dump_symbols(FILE *fp)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr sec_hdr;
	int num_hdrs,i;
	fseek(fp,(off_t)0,SEEK_SET);
	read_ELF_file_header(fp, &ehdr);
	num_hdrs=ehdr.e_shnum;
	for(i=0;i<num_hdrs;i++)
	{
		if(read_ELF_section_header(i,&sec_hdr,fp)==-1)
		{
			printf("Wrong Section to read\n");
		}
		else
		{
			if((sec_hdr.sh_type==SHT_SYMTAB)||(sec_hdr.sh_type==SHT_DYNSYM))			
			{
				printf("\n[section %3d] contains ",i);
				process_symtab(i,fp);
				
			}
					
		}
	}
}

void process_dynamic(FILE *fp)
{
	if(!fp)
	{
		printf("invalid file handle or file not opened\n");
		return;
	}
	
}
#ifndef STANDALONE_DISASM
int main(int argc, char *argv[])
{
	InitDisasm();
	FILE *elffile,*logfile;
	char *temp;
	int itr,do_section=0,do_symbols=0,do_proghdr=0;
	if(argc<3)
	{	
		printf("%s <elffile> <symbol> and/or <section> and/or <proghdr> and <logfile>\n",argv[0]);
		exit(0);
	}
	if (argc>2)
	{
		for(itr=2;itr<argc;itr++)
		{
			temp=(char*)malloc(strlen(argv[itr])*sizeof(char)+1);
			strcpy(temp,argv[itr]);
			if(strcmp(temp,"section")==0)
				do_section=1;
			if(strcmp(temp,"symbol")==0)
				do_symbols=1;
			if(strcmp(temp,"proghdr")==0)
				do_proghdr=1;
			free(temp);
		}
	}
	elffile=fopen(argv[1],"r");
	if(!elffile)
	{
		perror("open");
		exit(0);
	}
	logfile=fopen(argv[3],"w");
	if(!logfile)
	{
		perror("open");
		exit(0);
	}
	if(do_section==1)
	{
		display_sections(elffile);
		printf("-=|finished sections|=-\n");
	}
	if(do_symbols==1)
	{
		dump_symbols(elffile);
		printf("-=|finished symbols|=-\n");
	}
	if(do_proghdr==1)
	{
		display_proghdr(elffile,logfile);
		printf("-=|finished proghdr|=-\n");
	}
	fclose(elffile);
	
}
#endif
