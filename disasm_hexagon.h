#ifndef __DISASM__H__
#define __DISASM__H__

#include <Windows.h>
#include <tchar.h>
#include <string>
#include <bitset>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <stdint.h>
#include <locale>

#define LOOP_PACKET_MAX_COUNT 4
enum ICLASS:UINT16 {
	RESERVED0=0,
	RESERVED1=1,
	RESERVED2=2,
	RESERVED3=3,
	LD_ST_REL=4,
	J=5,
	CR=6,
	A32_7=7,
	XTYPE_S_8=8,
	LD=9,
	ST=10,
	ALU32=11,
	XTYPE_S_12=12,
	XTYPE_ALU64=13,
	XTYPE_M=14,
	A32_15=15
};

struct ins_raw_format{
	ICLASS cls;
	char bits[29];
	char * cmd;
};


//Instruction Class

//Slot number for cpu pipelining
enum PIPELINE_SLOT:UINT8 {
	SLOT0=0, //LD,ST,ALU32,SYSTEM
	SLOT1=1, //LD,ALU32
	SLOT2=2, //XTYPE,ALU32,J,JR
	SLOT3=3  //XTYPE,ALU32,J,CR
};

//Loop Parse bit flags
enum PARSEBITFLAGS
{
    PARSE_FLAGS_RESERVED,
    PARSE_FLAGS_NOT_LAST_ONE,
	PARSE_FLAGS_NOT_LAST_TWO,
	PARSE_FLAGS_LAST
};	
PARSEBITFLAGS GetParseBits(std::bitset<2> bits);

class class_hexagon_ins{
public:
	ICLASS Cls;
	std::bitset<28> Bits;
	ins_raw_format raw;
	class_hexagon_ins(ICLASS cls,std::bitset<28> bits);
};
class splitstring : public std::string {
    std::vector<std::string> flds;
public:
    splitstring(char *s) : std::string(s) { };
    std::vector<std::string>& split(char delim, int rep=0);
};

//put diff_blah if there are multiple instruction choices...val for diff values
//	reg for possible register
void xor_ins_with_txt(std::vector<ins_raw_format*> const& fmt,ins_raw_format raw,char** cmd);
//void xor_ins_with_txt(std::vector<ins_raw_format*> fmt,ins_raw_format raw,char** cmd);
std::bitset<32> GetCommand(const char bits[4]);
ICLASS GetIClass(std::bitset<4> bits);
void GetRegisterStr(std::bitset<5> reg_bits, char** reg);
ins_raw_format * Get_Ins_Raw(char bits[32],char * command);
void Add_ins_to_vector();
void GetInsClass(std::bitset<32> bits,FILE* log);
void InsPostProcessing(ins_raw_format * ins_str_bits, std::bitset<28> ins_bitset,char** cmd);
void Disassemble(uint8_t* buffer, int length,FILE* log);
int InitDisasm();
#endif