#include "disasm_hexagon.h"

std::vector<ins_raw_format*> v_ins_ld_st,v_ins_xts, v_ins_xt64;
std::vector<ins_raw_format*> v_ins_jr, v_ins_ld, v_ins_xtm;
std::vector<ins_raw_format*> v_ins_cr, v_ins_st, v_ins_a3215;
std::vector<ins_raw_format*> v_ins_a327, v_ins_xts2, v_ins_alu32;
int filePos = 0;
bool ins_raw_format_comparer (ins_raw_format* i,ins_raw_format* j) 
{
	return (i->cls < j->cls);
}
using namespace std;
#ifdef STANDALONE_DISASM
int _tmain(int argc, _TCHAR* argv[])
{	
	uint8_t * buffer[0x1000]="";
	DWORD numBytes;
	HANDLE hFile = CreateFile(argv[1],GENERIC_READ,FILE_SHARE_READ,
		NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	ReadFile(hFile,buffer,0x1000,&numBytes,NULL);
	Disassemble(buffer, numBytes);
	int err = GetLastError();
	CloseHandle(hFile);
	return 0;
}
#endif
int InitDisasm()
{
	Add_ins_to_vector();
	return 0;
}
void Disassemble(uint8_t* buffer, int length,FILE* log)
{
	std::string progress = "";
	if(length < 8)
	{
		goto ErrorExit;
	}
	
	int chunk = length/100;
	if(chunk<=1)
	{
		chunk=2;
	}
	int prog_counter = 1;
	int perc_last=0;
	int modulo = length/500;
	if(modulo<=1)
	{
		modulo=2;
	}
	for(unsigned int i =0; i<length-4;i+=4)
	{
		int test = (length-i)%modulo;
		if(test==0)
		{
			printf("%s\\",progress.c_str());
		}
		else if(test==1)
		{
			printf("%s|",progress.c_str());
		}
		else if(test==2)
		{
			printf("%s/",progress.c_str());
		}
		else if(test==3)
		{
			printf("%s-",progress.c_str());
		}
		int perc = (i*100)/length;
		if(perc>perc_last)
		{
			progress+="=";
			perc_last=perc;
		}
		printf("\r");
		prog_counter++;
		ULONGLONG val=0,val1=0,val2=0,val3=0,val4 = 0;
		val1=buffer[i+3];
		val1&=0x00000000000000FF;
		val1=val1<<24;
		val2=buffer[i+2];
		val2&=0x00000000000000FF;
		val2=val2<<16;
		val3=buffer[i+1];
		val3&=0x00000000000000FF;
		val3=val3<<8;
		val4=buffer[i];
		val4&=0x00000000000000FF;
		val=val1|val2|val3|val4;
		std::bitset<32> bits(val);
		GetInsClass(bits,log);
	}
ErrorExit:
	return;
}
//TODO: Fix the local variable return for reg and num
void GetRegisterStr(std::bitset<5> reg_bits, char** reg)
{
	*reg = new char[255];
	sprintf(*reg,"R%d",reg_bits.to_ulong());
}
ICLASS GetIClass(std::bitset<4> bits)
{
	return (ICLASS)bits.to_ulong();
}
PARSEBITFLAGS GetParseBits(std::bitset<2> bits)
{
	return(PARSEBITFLAGS)bits.to_ulong();
}
//Revisit this check for the bits to be equal between temp and ins_bits
void GetInsClass(std::bitset<32> bits, FILE* log)
{
	ins_raw_format* raw_proc=NULL;
	char* cmd_raw = NULL;
	std::bitset<4>cls(0);
	cls.set(0,bits[28]);
	cls.set(1,bits[29]);
	cls.set(2,bits[30]);
	cls.set(3,bits[31]);
	ICLASS iCls =GetIClass(cls);
	int blah = cls._Getword(0);
	std::bitset<28> ins_bits(0);
	std::bitset<28> *hey = NULL;
	
	for(int i=0;i<28;i++)
	{
		ins_bits.set(i,bits[i]);
	}
	class_hexagon_ins* ins = new class_hexagon_ins(iCls,ins_bits);

	switch (iCls)
	{
	case LD_ST_REL:
		xor_ins_with_txt(v_ins_ld_st,ins->raw,&cmd_raw);
		break;
	case J:
		xor_ins_with_txt(v_ins_jr,ins->raw,&cmd_raw);
		break;
	case CR:
		xor_ins_with_txt(v_ins_cr,ins->raw,&cmd_raw);
		break;
	case A32_7:
		xor_ins_with_txt(v_ins_a327,ins->raw,&cmd_raw);
		break;
	case XTYPE_S_8:
		xor_ins_with_txt(v_ins_xts,ins->raw,&cmd_raw);
		break;
	case LD:
		xor_ins_with_txt(v_ins_ld,ins->raw,&cmd_raw);
		break;
	case ST:
		xor_ins_with_txt(v_ins_st,ins->raw,&cmd_raw);
		break;
	case ALU32:
		xor_ins_with_txt(v_ins_alu32,ins->raw,&cmd_raw);
		break;
	case XTYPE_S_12:
		xor_ins_with_txt(v_ins_xts2,ins->raw,&cmd_raw);
		break;
	case XTYPE_ALU64:
		xor_ins_with_txt(v_ins_xts,ins->raw,&cmd_raw);
		break;
	case XTYPE_M:
		xor_ins_with_txt(v_ins_xtm,ins->raw,&cmd_raw);
		break;
	case A32_15:
		xor_ins_with_txt(v_ins_a3215,ins->raw,&cmd_raw);
		break;
	default:
		break;
	}
	if(NULL!= cmd_raw)
	{
		size_t length= strnlen(cmd_raw,260);
		if(length>0)
		{
			fwrite(cmd_raw,length,1,log);
		}
		delete[260] cmd_raw;
		cmd_raw = NULL;
	}
}
bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}
enum NUMTYPE{
	sign =0,
	unsign=1,
	na=2
};
struct ins_pars_offsets{
	char type;
	int count;
	int offset;
	NUMTYPE num_t;
};
struct ins_pos_char{
	vector<pair<char,int>> placement;
	char type;
};
void InsPostProcessing(ins_raw_format * ins_str_bits, std::bitset<28> ins_bitset,char** cmd)
{
	//collection of types and counts i.e 
	//{("iiiii",5),("uu",2),("vv",2),("IIIII",5),("N",1)}
	vector<ins_pars_offsets*> v_ins_pars_offsets;
	vector<ins_pos_char*> v_pos_chars;
	stringstream ss_ins;
	locale loc;
	std::string str_ins_bits(ins_str_bits->bits);
	std::string str_orig_cmd(ins_str_bits->cmd);
	std::string str_cmd(ins_str_bits->cmd);

	for (size_t i=0; i<str_cmd.length(); ++i)
	{
		ss_ins << tolower(str_cmd[i],loc);
	}
	str_cmd = ss_ins.str();
	//not found = -1 or 0xffffffff
	//found = first position 
	int rd_pos=str_ins_bits.find("ddddd");
	int rs_pos=str_ins_bits.find("sssss");
	int rx_pos=str_ins_bits.find("xxxxx");
	int rt_pos=str_ins_bits.find("ttttt");
	if(rd_pos != -1)
	{
		std::bitset<5> rd_bits(0);
		rd_bits.set(0,ins_bitset[0]);
		rd_bits.set(1,ins_bitset[1]);
		rd_bits.set(2,ins_bitset[2]);
		rd_bits.set(3,ins_bitset[3]);
		rd_bits.set(4,ins_bitset[4]);
		int found_long = str_cmd.find("rdd");
		int found_short = str_cmd.find("rd");
		if(found_long>=0&&found_long<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rd_bits,&reg);
			replace(str_orig_cmd,"Rdd",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
		else if(found_short>=0&&found_short<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rd_bits,&reg);
			replace(str_orig_cmd,"Rd",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
	}
	if(rs_pos != -1)
	{
		std::bitset<5> rs_bits(0);
		rs_bits.set(0,ins_bitset[16]);
		rs_bits.set(1,ins_bitset[17]);
		rs_bits.set(2,ins_bitset[18]);
		rs_bits.set(3,ins_bitset[19]);
		rs_bits.set(4,ins_bitset[20]);
		int found_long = str_cmd.find("rss");
		int found_short = str_cmd.find("rs");
		if(found_long>=0&&found_long<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rs_bits,&reg);
			replace(str_orig_cmd,"Rss",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
		else if(found_short>=0&&found_short<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rs_bits,&reg);
			replace(str_orig_cmd,"Rs",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
	}
	if(rx_pos != -1)
	{
		std::bitset<5> rx_bits(0);
		rx_bits.set(0,ins_bitset[0]);
		rx_bits.set(1,ins_bitset[1]);
		rx_bits.set(2,ins_bitset[2]);
		rx_bits.set(3,ins_bitset[3]);
		rx_bits.set(4,ins_bitset[4]);
		int found_long = str_cmd.find("rxx");
		int found_short = str_cmd.find("rx");
		if(found_long>=0&&found_long<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rx_bits,&reg);
			replace(str_orig_cmd,"Rxx",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
		else if(found_short>=0&&found_short<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rx_bits,&reg);
			replace(str_orig_cmd,"Rx",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
	}
	if(rt_pos != -1)
	{
		std::bitset<5> rt_bits(0);
		rt_bits.set(0,ins_bitset[8]);
		rt_bits.set(1,ins_bitset[9]);
		rt_bits.set(2,ins_bitset[10]);
		rt_bits.set(3,ins_bitset[11]);
		rt_bits.set(4,ins_bitset[12]);
		int found_long = str_cmd.find("rtt");
		int found_short = str_cmd.find("rt");
		if(found_long>=0&&found_long<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rt_bits,&reg);
			replace(str_orig_cmd,"Rtt",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
		else if(found_short>=0&&found_short<str_cmd.length())
		{
			char * reg = NULL;
			GetRegisterStr(rt_bits,&reg);
			replace(str_orig_cmd,"Rt",reg);
			if(NULL !=reg)
			{
				delete[255] reg;
				reg = NULL;
			}
		}
	}
	size_t len = str_cmd.length();
	const char * str = str_cmd.c_str();
	*cmd = new char[260];
	sprintf_s(*cmd,260,str);
	//delete[] str;
	//roll through the tokens and find the # signs, then replace that with 
	char * pch;
	char * chr_orig_cmd = new char[132];
	ZeroMemory(chr_orig_cmd,132);
	sprintf_s(chr_orig_cmd,132,"%s",str_orig_cmd.c_str());
	pch = strtok (chr_orig_cmd," ,():+=");
	vector<std::string> replacement_tokens;
	while (pch != NULL)
	{
		if(pch[0] == '#')
		{
			if(pch[1] == 's')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=sign;
				pars->type='i';
				v_ins_pars_offsets.push_back(pars);
			}
			if(pch[1] == 'S')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=sign;
				pars->type='I';
				v_ins_pars_offsets.push_back(pars);
			}
			if(pch[1] == 'u')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=sign;
				pars->type='i';
				v_ins_pars_offsets.push_back(pars);
			}
			if(pch[1] == 'U')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=unsign;
				pars->type='I';
				v_ins_pars_offsets.push_back(pars);
			}
			if(pch[1] == 'r')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=sign;
				pars->type='i';
				v_ins_pars_offsets.push_back(pars);
			}
			if(pch[1] == 'R')
			{
				ins_pars_offsets * pars=new ins_pars_offsets();
				pars->num_t=unsign;
				pars->type='I';
				v_ins_pars_offsets.push_back(pars);
			}
			replacement_tokens.push_back(pch);
		}
		pch = strtok (NULL, " ,():+=");
	}
	//roll through each parsed number type and get its value
	for(vector<ins_pars_offsets*>::iterator it = v_ins_pars_offsets.begin();
		it<v_ins_pars_offsets.end();++it)
	{
		ins_pos_char * ins_cp = new ins_pos_char();
		ins_pars_offsets * temp_pars = *it;
		ins_cp->type=temp_pars->type;
		for(int i=0;i<str_ins_bits.length();i++)
		{
			if(str_ins_bits.at(i)==temp_pars->type)
			{
				pair<char,int> pos_ch(temp_pars->type,i);
				ins_cp->placement.push_back(pos_ch);
			}
		}
		v_pos_chars.push_back(ins_cp);
	}
	vector<std::string> numbers_for_cmd;
	for(vector<ins_pos_char*>::iterator it = v_pos_chars.begin();
		it<v_pos_chars.end();++it)
	{
		int count=0;
		ins_pos_char * temp_pars = *it;
		char temp_str[100] ="";
		bitset<28> temp_bits(0);
		int size_of_vec = temp_pars->placement.size();
		if(temp_pars->type=='s' || temp_pars->type=='S')
		{
			for(vector<pair<char,int>>::iterator iter = temp_pars->placement.begin();
				iter<temp_pars->placement.end();++iter)
			{
				int pos=iter->second;
				temp_bits.set(count,ins_bitset[pos]);
				count++;
			}
			sprintf_s(temp_str,"%x",temp_bits.to_ullong());
			numbers_for_cmd.push_back(temp_str);
		}
		else
		{
			for(vector<pair<char,int>>::iterator iter = temp_pars->placement.begin();
				iter<temp_pars->placement.end();++iter)
			{
				int pos=iter->second;
				temp_bits.set(count,ins_bitset[pos]);
				count++;
			}
			sprintf_s(temp_str,"\"%x\"",temp_bits.to_ullong());
			numbers_for_cmd.push_back(temp_str);
		}
	}
	int count_tokens = 0;
	for(vector<std::string>::iterator iter = replacement_tokens.begin();
			iter<replacement_tokens.end();++iter)
	{
		replace(str_orig_cmd,*iter,numbers_for_cmd[count_tokens]);
		count_tokens++;
	}
	sprintf_s(*cmd,100,"%s\n",str_orig_cmd.c_str());
	/*delete &str_ins_bits;
	delete &str_orig_cmd;
	delete &str_cmd;*/
}
class_hexagon_ins::class_hexagon_ins(ICLASS cls, std::bitset<28> bits)
{
	this->Cls=cls;
	this->Bits = bits;
	this->raw.cls=cls;
	ZeroMemory(this->raw.bits,29);
	for(int i=0,j=27; i<28;i++,j--)
	{
		this->raw.bits[j]=bits[i]+0x30;
	}
	this->raw.cmd="";
}
vector<string>& splitstring::split(char delim, int rep) {
    if (!flds.empty()) flds.clear();  // empty vector if necessary
    string work = data();
    string buf = "";
    int i = 0;
    while (i < work.length()) {
        if (work[i] != delim)
            buf += work[i];
        else if (rep == 1) {
            flds.push_back(buf);
            buf = "";
        } else if (buf.length() > 0) {
            flds.push_back(buf);
            buf = "";
        }
        i++;
    }
    if (!buf.empty())
        flds.push_back(buf);
    return flds;
}
ins_raw_format * Get_Ins_Raw(char bits[32],char * command)
{
	ins_raw_format * raw = new ins_raw_format();
	std::bitset<4>cls(0);
	cls.set(0,bits[3]-'0');
	cls.set(1,bits[2]-'0');
	cls.set(2,bits[1]-'0');
	cls.set(3,bits[0]-'0');
	raw->cls =GetIClass(cls);
	raw->cmd = command;
	for(int i=0; i<28;i++)
	{
		raw->bits[i]=bits[i+4];
	}
	return raw;
}
void xor_ins_with_txt(std::vector<ins_raw_format*> const& fmt,ins_raw_format raw,char** cmd)
{
	char* pTemp = new char[260];
	ZeroMemory(pTemp,260);
	BOOL found = TRUE;
	for(auto it = fmt.begin(); it != fmt.end(); ++it) {
		ins_raw_format *temp = *it;
		//roll through all bits
		for(int i=0,j=27; i<28;i++,j--)
		{
			//compare where there is a 1 or 0 in the template
			if(temp->bits[i]=='1'||temp->bits[i]=='0')
			{
				if(raw.bits[j] != temp->bits[i])
				{
					found=FALSE;
					break;
				}
			}
			found=TRUE;
		}
		if(found)
		{
			sprintf_s(pTemp,260,temp->cmd);
			InsPostProcessing(temp,std::bitset<28>(raw.bits),&pTemp);
		}
	}
	*cmd = pTemp;
}
void Add_ins_to_vector()
{
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001110sssssPP-ttiiiiiiddddd","if(Pt) Rdd=memd(Rs+#u6:3)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001000sssssPP-ttiiiiiiddddd","if(Pt) Rd=memb(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001010sssssPP-ttiiiiiiddddd","if(Pt) Rd=memh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001001sssssPP-ttiiiiiiddddd","if(Pt) Rd=memub(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001011sssssPP-ttiiiiiiddddd","if(Pt) Rd=memuh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000001100sssssPP-ttiiiiiiddddd","if(Pt) Rd=memw(Rs+#u6:2)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000000110sssssPPitttttiiiii-vv","if(Pv) memd(Rs+#u6:3)=Rtt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000000000sssssPPitttttiiiii-vv","if(Pv) memb(Rs+#u6:0)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000000010sssssPPitttttiiiii-vv","if(Pv) memh(Rs+#u6:1)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000000011sssssPPitttttiiiii-vv","if(Pv) memh(Rs+#u6:1)=Rt.H"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000000100sssssPPitttttiiiii-vv","if(Pv) memw(Rs+#u6:2)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011110sssssPP-ttiiiiiiddddd","if(Pt.new) Rdd=memd(Rs+#u6:3)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011000sssssPP-ttiiiiiiddddd","if(Pt.new) Rd=memb(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011010sssssPP-ttiiiiiiddddd","if(Pt.new) Rd=memh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011001sssssPP-ttiiiiiiddddd","if(Pt.new) Rd=memub(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011011sssssPP-ttiiiiiiddddd","if(Pt.new) Rd=memuh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000011100sssssPP-ttiiiiiiddddd","if(Pt.new) Rd=memw(Rs+#u6:2)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101110sssssPP-ttiiiiiiddddd","if(!Pt) Rdd=memd(Rs+#u6:3)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101000sssssPP-ttiiiiiiddddd","if(!Pt) Rd=memb(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101010sssssPP-ttiiiiiiddddd","if(!Pt) Rd=memh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101001sssssPP-ttiiiiiiddddd","if(!Pt) Rd=memub(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101011sssssPP-ttiiiiiiddddd","if(!Pt) Rd=memuh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000101100sssssPP-ttiiiiiiddddd","if(!Pt) Rd=memw(Rs+#u6:2)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000100110sssssPPitttttiiiii-vv","if(!Pv) memd(Rs+#u6:3)=Rtt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000100000sssssPPitttttiiiii-vv","if(!Pv) memb(Rs+#u6:0)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000100010sssssPPitttttiiiii-vv","if(!Pv) memh(Rs+#u6:1)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000100011sssssPPitttttiiiii-vv","if(!Pv) memh(Rs+#u6:1)=Rt.H"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000100100sssssPPitttttiiiii-vv","if(!Pv) memw(Rs+#u6:2)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111110sssssPP-ttiiiiiiddddd","if(!Pt.new) Rdd=memd(Rs+#u6:3)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111000sssssPP-ttiiiiiiddddd","if(!Pt.new) Rd=memb(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111010sssssPP-ttiiiiiiddddd","if(!Pt.new) Rd=memh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111001sssssPP-ttiiiiiiddddd","if(!Pt.new) Rd=memub(Rs+#u6:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111011sssssPP-ttiiiiiiddddd","if(!Pt.new) Rd=memuh(Rs+#u6:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01000111100sssssPP-ttiiiiiiddddd","if(!Pt.new) Rd=memw(Rs+#u6:2)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1110iiiiiPPiiiiiiiiiddddd","Rdd=memd(#u16:3)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1000iiiiiPPiiiiiiiiiddddd","Rd=memb(#u16:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1010iiiiiPPiiiiiiiiiddddd","Rd=memh(#u16:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1001iiiiiPPiiiiiiiiiddddd","Rd=memub(#u16:0)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1011iiiiiPPiiiiiiiiiddddd","Rd=memuh(#u16:1)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii1100iiiiiPPiiiiiiiiiddddd","Rd=memw(#u16:2)"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii0110iiiiiPPitttttiiiiiiii","memd(#u16:3)=Rtt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii0000iiiiiPPitttttiiiiiiii","memb(#u16:0)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii0010iiiiiPPitttttiiiiiiii","memh(#u16:1)=Rt"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii0011iiiiiPPitttttiiiiiiii","memh(#u16:1)=Rt.H"));
	v_ins_ld_st.push_back(Get_Ins_Raw("01001ii0100iiiiiPPitttttiiiiiiii","memw(#u16:2)=Rt"));
	v_ins_cr.push_back(Get_Ins_Raw("01100000000sssssPP-iiiii---ii---","loop0(#r7:2,Rs)"));
	v_ins_cr.push_back(Get_Ins_Raw("01100000001sssssPP-iiiii---ii---","loop1(#r7:2,Rs)"));
	v_ins_cr.push_back(Get_Ins_Raw("01100000101sssssPP-iiiii---ii---","p3=sp1loop0(#r7:2,Rs)"));
	v_ins_cr.push_back(Get_Ins_Raw("01100000110sssssPP-iiiii---ii---","p3=sp2loop0(#r7:2,Rs)"));
	v_ins_cr.push_back(Get_Ins_Raw("01100000111sssssPP-iiiii---ii---","p3=sp3loop0(#r7:2,Rs)"));
	v_ins_cr.push_back(Get_Ins_Raw("01100010001sssssPP---------ddddd","Cd=Rs"));
	v_ins_cr.push_back(Get_Ins_Raw("01101001000IIIIIPP-iiiiiIIIii-II","loop0(#r7:2,#U10)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101001001IIIIIPP-iiiiiIIIii-II","loop1(#r7:2,#U10)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101001101IIIIIPP-iiiiiIIIii-II","p3=sp1loop0(#r7:2,#U10)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101001110IIIIIPP-iiiiiIIIii-II","p3=sp2loop0(#r7:2,#U10)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101001111IIIIIPP-iiiiiIIIii-II","p3=sp3loop0(#r7:2,#U10)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011100---ssPP------------dd","Pd=any8(Ps)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011101---ssPP------------dd","Pd=all8(Ps)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011000---ssPP----tt------dd","Pd=and(Ps,Pt)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011001---ssPP----tt------dd","Pd=or(Ps,Pt)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011010---ssPP----tt------dd","Pd=xor(Ps,Pt)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011011---ssPP----tt------dd","Pd=and(Pt,!Ps)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011110---ssPP------------dd","Pd=not(Ps)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101011111---ssPP----tt------dd","Pd=or(Pt,!Ps)"));
	v_ins_cr.push_back(Get_Ins_Raw("01101010000sssssPP---------ddddd","Rd=Cs"));
	v_ins_cr.push_back(Get_Ins_Raw("01101100001-----PP------000-----","brkpt"));
	v_ins_jr.push_back(Get_Ins_Raw("01010000101sssssPP--------------","callr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("01010001000sssssPP----uu--------","if (Pu) callr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("01010001001sssssPP----uu--------","if (!Pu) callr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("01010010100sssssPP--------------","jumpr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("01010011010sssssPP----uu--------","if (Pu) jumpr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("01010011011sssssPP----uu--------","if (!Pu) jumpr Rs"));
	v_ins_jr.push_back(Get_Ins_Raw("010101000-------PP-iiiii---iii--","trap0(#u8)"));
	v_ins_jr.push_back(Get_Ins_Raw("010101001-------PP-iiiii---iii--","trap1(#u8)"));
	v_ins_jr.push_back(Get_Ins_Raw("01010110110sssssPP000-----------","icinva(Rs)"));
	v_ins_jr.push_back(Get_Ins_Raw("0101011111000000PP0---0000000010","isync"));
	v_ins_jr.push_back(Get_Ins_Raw("0101100iiiiiiiiiPPiiiiiiiiiiiii-","jump #r22:2"));
	v_ins_jr.push_back(Get_Ins_Raw("0101101iiiiiiiiiPPiiiiiiiiiiiii-","call #r22:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011101ii0iiiiiPPi00-uuiiiiiii-"," (Pu) call #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011101ii1iiiiiPPi00-uuiiiiiii-","if (!Pu) call #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii0iiiiiPPi00-uuiiiiiii-","if (Pu) jump #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii1iiiiiPPi00-uuiiiiiii-","if (!Pu) jump #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii0iiiiiPPi01-uuiiiiiii-","if (Pu.new) jump:nt #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii0iiiiiPPi11-uuiiiiiii-","if (Pu.new) jump:t #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii1iiiiiPPi01-uuiiiiiii-","if (!Pu.new) jump:nt #r15:2"));
	v_ins_jr.push_back(Get_Ins_Raw("01011100ii1iiiiiPPi11-uuiiiiiii-","if (!Pu.new) jump:t #r15:2"));
	v_ins_a327.push_back(Get_Ins_Raw("01110001ii1xxxxxPPiiiiiiiiiiiiii","Rx.L=#u16"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000011sssssPP---------ddddd","Rd=Rs"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000000sssssPP---------ddddd","Rd=aslh(Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000001sssssPP---------ddddd","Rd=asrh(Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000101sssssPP---------ddddd","Rd=sxtb(Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000111sssssPP---------ddddd","Rd=sxth(Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110000110sssssPP---------ddddd","Rd=zxth(Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110010ii1xxxxxPPiiiiiiiiiiiiii","Rx.H=#u16"));
	v_ins_a327.push_back(Get_Ins_Raw("011100110uusssssPP0iiiiiiiiddddd","Rd=mux(Pu,Rs,#s8)"));
	v_ins_a327.push_back(Get_Ins_Raw("011100111uusssssPP0iiiiiiiiddddd","Rd=mux(Pu,#s8,Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("011101000uusssssPP0iiiiiiiiddddd","if (Pu) Rd=add(Rs,#s8)"));
	v_ins_a327.push_back(Get_Ins_Raw("011101000uusssssPP1iiiiiiiiddddd","if (Pu.new) Rd=add(Rs,#s8)"));
	v_ins_a327.push_back(Get_Ins_Raw("011101001uusssssPP0iiiiiiiiddddd","if (!Pu) Rd=add(Rs,#s8)"));
	v_ins_a327.push_back(Get_Ins_Raw("011101001uusssssPP1iiiiiiiiddddd","if (!Pu.new) Rd=add(Rs,#s8)"));
	v_ins_a327.push_back(Get_Ins_Raw("0111010100isssssPPiiiiiiiii---dd","Pd=cmp.eq(Rs,#s10)"));
	v_ins_a327.push_back(Get_Ins_Raw("0111010101isssssPPiiiiiiiii---dd","Pd=cmp.gt(Rs,#s10)"));
	v_ins_a327.push_back(Get_Ins_Raw("01110101100sssssPPiiiiiiiii---dd","Pd=cmp.gtu(Rs,#u9)"));
	v_ins_a327.push_back(Get_Ins_Raw("0111011000isssssPPiiiiiiiiiddddd","Rd=and(Rs,#s10)"));
	v_ins_a327.push_back(Get_Ins_Raw("0111011010isssssPPiiiiiiiiiddddd","Rd=or(Rs,#s10)"));
	v_ins_a327.push_back(Get_Ins_Raw("0111011001isssssPPiiiiiiiiiddddd","Rd=sub(#s10,Rs)"));
	v_ins_a327.push_back(Get_Ins_Raw("01111000ii-iiiiiPPiiiiiiiiiddddd","Rd=#s16"));
	v_ins_a327.push_back(Get_Ins_Raw("0111101uuIIIIIIIPPIiiiiiiiiddddd","Rd=mux(Pu,#s8,#S8)"));
	v_ins_a327.push_back(Get_Ins_Raw("01111100-IIIIIIIPPIiiiiiiiiddddd","Rdd=combine(#s8,#S8)"));
	v_ins_a327.push_back(Get_Ins_Raw("01111111--------PP--------------","nop"));
	v_ins_a327.push_back(Get_Ins_Raw("011111100uu-iiiiPP0iiiiiiiiddddd","if (Pu) Rd=#s12"));
	v_ins_a327.push_back(Get_Ins_Raw("011111100uu-iiiiPP1iiiiiiiiddddd","if (Pu.new) Rd=#s12"));
	v_ins_a327.push_back(Get_Ins_Raw("011111101uu-iiiiPP0iiiiiiiiddddd","if (!Pu) Rd=#s12"));
	v_ins_a327.push_back(Get_Ins_Raw("011111101uu-iiiiPP1iiiiiiiiddddd","if (!Pu.new) Rd=#s12"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP------110ddddd","Rdd=abs(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP------101ddddd","Rdd=neg(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP------100ddddd","Rdd=not(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("10000001IIIsssssPPiiiiiiIIIddddd","Rdd=extractu(Rss,#u6,#U6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000011-sssssPP------100ddddd","Rdd=deinterleave(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000011-sssssPP------101ddddd","Rdd=interleave(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP------111ddddd","Rdd=vconj(Rss):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPP------100ddddd","Rdd=vsathub(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPP------101ddddd","Rdd=vsatwuh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPP------110ddddd","Rdd=vsatwh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPP------111ddddd","Rdd=vsathb(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPPiiiiii000ddddd","Rdd=asr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPPiiiiii001ddddd","Rdd=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000000-sssssPPiiiiii010ddddd","Rdd=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP------100ddddd","Rdd=vabsh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP------101ddddd","Rdd=vabsh(Rss):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP00iiii000ddddd","Rdd=vasrh(Rss,#u4)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP00iiii001ddddd","Rdd=vlsrh(Rss,#u4)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000010-sssssPP00iiii010ddddd","Rdd=vaslh(Rss,#u4)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP------110ddddd","Rdd=vabsw(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP------111ddddd","Rdd=vabsw(Rss):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP0iiiii000ddddd","Rdd=vasrw(Rss,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP0iiiii001ddddd","Rdd=vlsrw(Rss,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000000001-sssssPP0iiiii010ddddd","Rdd=vaslw(Rss,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("10000011IIIsssssPPiiiiiiIIIxxxxx","Rxx=insert(Rss,#u6,#U6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii000xxxxx","Rxx-=asr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii001xxxxx","Rxx-=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii010xxxxx","Rxx-=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii100xxxxx","Rxx+=asr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii101xxxxx","Rxx+=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001000-sssssPPiiiiii110xxxxx","Rxx+=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii000xxxxx","Rxx&=asr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii001xxxxx","Rxx&=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii010xxxxx","Rxx&=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii100xxxxx","Rxx|=asr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii101xxxxx","Rxx|=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001001-sssssPPiiiiii110xxxxx","Rxx|=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001010-sssssPPiiiiii001xxxxx","Rxx^=lsr(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000001010-sssssPPiiiiii010xxxxx","Rxx^=asl(Rss,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010001-sssssPP------00-ddddd","Rdd=sxtw(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010110-sssssPPiiiiii------dd","Pd=bitsclr(Rs,#u6)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010100-sssssPP0iiiii------dd","Pd=tstbit(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010001-sssssPP------01-ddddd","Rdd=vsplath(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010000-sssssPP------00-ddddd","Rdd=vsxtbh(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010000-sssssPP------10-ddddd","Rdd=vsxthw(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010000-sssssPP------01-ddddd","Rdd=vzxtbh(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010000-sssssPP------11-ddddd","Rdd=vzxthw(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000010101-sssssPP------------dd","Pd=Rs"));
	v_ins_xts.push_back(Get_Ins_Raw("10000110--------PP----tt---ddddd","Rdd=mask(Pt)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000011100isssssPPIIIIIIiiixxxxx","Rx=tableidxb(Rs,#u4,#S6):raw"));
	v_ins_xts.push_back(Get_Ins_Raw("1000011101isssssPPIIIIIIiiixxxxx","Rx=tableidxh(Rs,#u4,#S6):raw"));
	v_ins_xts.push_back(Get_Ins_Raw("1000011110isssssPPIIIIIIiiixxxxx","Rx=tableidxw(Rs,#u4,#S6):raw"));
	v_ins_xts.push_back(Get_Ins_Raw("1000011111isssssPPIIIIIIiiixxxxx","Rx=tableidxd(Rs,#u4,#S6):raw"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100001-sssssPP------00-ddddd","Rd=clb(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100001-sssssPP------01-ddddd","Rd=cl0(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100001-sssssPP------10-ddddd","Rd=cl1(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100011-sssssPP------00-ddddd","Rd=sat(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100010-sssssPP------10-ddddd","Rd=vrndwh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100010-sssssPP------11-ddddd","Rd=vrndwh(Rss):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100000-sssssPP------00-ddddd","Rd=vsathub(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100000-sssssPP------01-ddddd","Rd=vsatwh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100000-sssssPP------10-ddddd","Rd=vsatwuh(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100000-sssssPP------11-ddddd","Rd=vsathb(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100010-sssssPP------00-ddddd","Rd=vtrunohb(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100010-sssssPP------01-ddddd","Rd=vtrunehb(Rss)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100101----ssPP---------ddddd","Rd=Ps"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100100----ssPP----tt---ddddd","Rd=vitpack(Ps,Pt)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000100011-sssssPP0iiiii01-ddddd","Rd=vasrw(Rss,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------100ddddd","Rd=abs(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------101ddddd","Rd=abs(Rs):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------110ddddd","Rd=neg(Rs):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP------100ddddd","Rd=clb(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP------101ddddd","Rd=cl0(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP------110ddddd","Rd=cl1(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP------111ddddd","Rd=normamt(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP------100ddddd","Rd=ct0(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP------101ddddd","Rd=ct1(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("100011010IIsssssPP0iiiiiIIIddddd","Rd=extractu(Rs,#u5,#U5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP------110ddddd","Rd=brev(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP0iiiii000ddddd","Rd=setbit(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP0iiiii001ddddd","Rd=clrbit(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP0iiiii010ddddd","Rd=togglebit(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP------100ddddd","Rd=sath(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP------101ddddd","Rd=satuh(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP------110ddddd","Rd=satub(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110011-sssssPP------111ddddd","Rd=satb(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------111ddddd","Rd=swiz(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------00-ddddd","Rd=vsathb(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110010-sssssPP------01-ddddd","Rd=vsathub(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP------111ddddd","Rd=vsplatb(Rs)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP0iiiii000ddddd","Rd=asr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP0iiiii001ddddd","Rd=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110000-sssssPP0iiiii010ddddd","Rd=asl(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP0iiiii000ddddd","Rd=asr(Rs,#u5):rnd"));
	v_ins_xts.push_back(Get_Ins_Raw("1000110001-sssssPP0iiiii010ddddd","Rd=asl(Rs,#u5):sat"));
	v_ins_xts.push_back(Get_Ins_Raw("100011110IIsssssPP0iiiiiIIIxxxxx","Rx=insert(Rs,#u5,#U5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii000xxxxx","Rx-=asr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii001xxxxx","Rx-=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii010xxxxx","Rx-=asl(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii100xxxxx","Rx+=asr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii101xxxxx","Rx+=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111000-sssssPP0iiiii110xxxxx","Rx+=asl(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii000xxxxx","Rx&=asr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii001xxxxx","Rx&=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii010xxxxx","Rx&=asl(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii100xxxxx","Rx|=asr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii101xxxxx","Rx|=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111001-sssssPP0iiiii110xxxxx","Rx|=asl(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111010-sssssPP0iiiii001xxxxx","Rx^=lsr(Rs,#u5)"));
	v_ins_xts.push_back(Get_Ins_Raw("1000111010-sssssPP0iiiii010xxxxx","Rx^=asl(Rs,#u5)"));
	v_ins_ld.push_back(Get_Ins_Raw("1001000000011110PP0--------11110","deallocframe"));
	v_ins_ld.push_back(Get_Ins_Raw("10010010000sssssPP0--------ddddd","Rd=memw_locked(Rs)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010100000sssssPP0-------------","dcfetch(Rs)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1110sssssPPiiiiiiiiiddddd","Rdd=memd(Rs+#s11:3)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1000sssssPPiiiiiiiiiddddd","Rd=memb(Rs+#s11:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1010sssssPPiiiiiiiiiddddd","Rd=memh(Rs+#s11:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1001sssssPPiiiiiiiiiddddd","Rd=memub(Rs+#s11:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1011sssssPPiiiiiiiiiddddd","Rd=memuh(Rs+#s11:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii1100sssssPPiiiiiiiiiddddd","Rd=memw(Rs+#s11:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii0011sssssPPiiiiiiiiiddddd","Rd=memubh(Rs+#s11:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10010ii0101sssssPPiiiiiiiiiddddd","Rdd=memubh(Rs+#s11:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001110xxxxxPPu0--0iiiiddddd","Rdd=memd(Rx++#s4:3:circ (Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001110xxxxxPPu0--1----ddddd","Rdd=memd(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001000xxxxxPPu0--0iiiiddddd","Rd=memb(Rx++#s4:0:circ( Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001000xxxxxPPu0--1----ddddd","Rd=memb(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001010xxxxxPPu0--0iiiiddddd","Rd=memh(Rx++#s4:1:circ( Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001010xxxxxPPu0--1----ddddd","Rd=memh(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001001xxxxxPPu0--0iiiiddddd","Rd=memub(Rx++#s4:0:circ (Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001001xxxxxPPu0--1----ddddd","Rd=memub(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001011xxxxxPPu0--0iiiiddddd","Rd=memuh(Rx++#s4:1:circ (Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001011xxxxxPPu0--1----ddddd","Rd=memuh(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001100xxxxxPPu0--0iiiiddddd","Rd=memw(Rx++#s4:2:circ( Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011001100xxxxxPPu0--1----ddddd","Rd=memw(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011000011xxxxxPPu0--0iiiiddddd","Rd=memubh(Rx++#s4:1:cir c(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011000011xxxxxPPu0--1----ddddd","Rd=memubh(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011000101xxxxxPPu0--0iiiiddddd","Rdd=memubh(Rx++#s4:2:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011000101xxxxxPPu0--1----ddddd","Rdd=memubh(Rx++I:circ(Mu))"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011110xxxxxPP00---iiiiddddd","Rdd=memd(Rx++#s4:3)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011110xxxxxPP1-0ttiiiiddddd","if (Pt) Rdd=memd(Rx++#s4:3)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011110xxxxxPP1-1ttiiiiddddd","if (!Pt) Rdd=memd(Rx++#s4:3)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011000xxxxxPP00---iiiiddddd","Rd=memb(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011000xxxxxPP1-0ttiiiiddddd","if (Pt) Rd=memb(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011000xxxxxPP1-1ttiiiiddddd","if (!Pt) Rd=memb(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011010xxxxxPP00---iiiiddddd","Rd=memh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011010xxxxxPP1-0ttiiiiddddd","if (Pt) Rd=memh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011010xxxxxPP1-1ttiiiiddddd","if (!Pt) Rd=memh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011001xxxxxPP00---iiiiddddd","Rd=memub(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011001xxxxxPP1-0ttiiiiddddd","if (Pt) Rd=memub(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011001xxxxxPP1-1ttiiiiddddd","if (!Pt) Rd=memub(Rx++#s4:0)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011011xxxxxPP00---iiiiddddd","Rd=memuh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011011xxxxxPP1-0ttiiiiddddd","if (Pt) Rd=memuh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011011xxxxxPP1-1ttiiiiddddd","if (!Pt) Rd=memuh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011100xxxxxPP00---iiiiddddd","Rd=memw(Rx++#s4:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011100xxxxxPP1-0ttiiiiddddd","if (Pt) Rd=memw(Rx++#s4:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011011100xxxxxPP1-1ttiiiiddddd","if (!Pt) Rd=memw(Rx++#s4:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011010011xxxxxPP00---iiiiddddd","Rd=memubh(Rx++#s4:1)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011010101xxxxxPP00---iiiiddddd","Rdd=memubh(Rx++#s4:2)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101110xxxxxPPu0-------ddddd","Rdd=memd(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101000xxxxxPPu0-------ddddd","Rd=memb(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101010xxxxxPPu0-------ddddd","Rd=memh(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101001xxxxxPPu0-------ddddd","Rd=memub(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101011xxxxxPPu0-------ddddd","Rd=memuh(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011101100xxxxxPPu0-------ddddd","Rd=memw(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011100011xxxxxPPu0-------ddddd","Rd=memubh(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011100101xxxxxPPu0-------ddddd","Rdd=memubh(Rx++Mu)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111110xxxxxPPu0-------ddddd","Rdd=memd(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111000xxxxxPPu0-------ddddd","Rd=memb(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111010xxxxxPPu0-------ddddd","Rd=memh(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111001xxxxxPPu0-------ddddd","Rd=memub(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111011xxxxxPPu0-------ddddd","Rd=memuh(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011111100xxxxxPPu0-------ddddd","Rd=memw(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011110011xxxxxPPu0-------ddddd","Rd=memubh(Rx++Mu:brev)"));
	v_ins_ld.push_back(Get_Ins_Raw("10011110101xxxxxPPu0-------ddddd","Rdd=memubh(Rx++Mu:brev)"));
	v_ins_st.push_back(Get_Ins_Raw("1010000010011101PP000iiiiiiiiiii","allocframe(#u11:3)"));
	v_ins_st.push_back(Get_Ins_Raw("10100000101sssssPP-ttttt------dd","memw_locked(Rs,Pd)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10100000110sssssPP--------------","dczeroa(Rs)"));
	v_ins_st.push_back(Get_Ins_Raw("10100000000sssssPP--------------","dccleana(Rs)"));
	v_ins_st.push_back(Get_Ins_Raw("10100000001sssssPP--------------","dcinva(Rs)"));
	v_ins_st.push_back(Get_Ins_Raw("10100000010sssssPP--------------","dccleaninva(Rs)"));
	v_ins_st.push_back(Get_Ins_Raw("10100ii1110sssssPPitttttiiiiiiii","memd(Rs+#s11:3)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10100ii1000sssssPPitttttiiiiiiii","memb(Rs+#s11:0)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10100ii1010sssssPPitttttiiiiiiii","memh(Rs+#s11:1)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10100ii1011sssssPPitttttiiiiiiii","memh(Rs+#s11:1)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10100ii1100sssssPPitttttiiiiiiii","memw(Rs+#s11:2)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001110xxxxxPPuttttt0-----1-","memd(Rx++I:circ(Mu))=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001110xxxxxPPuttttt0iiii-0-","memd(Rx++#s4:3:circ(Mu)) =Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001000xxxxxPPuttttt0-----1-","memb(Rx++I:circ(Mu))=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001000xxxxxPPuttttt0iiii-0-","memb(Rx++#s4:0:circ(Mu)) =Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001010xxxxxPPuttttt0-----1-","memh(Rx++I:circ(Mu))=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001010xxxxxPPuttttt0iiii-0-","memh(Rx++#s4:1:circ(Mu)) =Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001011xxxxxPPuttttt0-----1-","memh(Rx++I:circ(Mu))=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101001011xxxxxPPuttttt0iiii-0-","memh(Rx++#s4:1:circ(Mu)) =Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101001100xxxxxPPuttttt0-----1-","memw(Rx++I:circ(Mu))=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101001100xxxxxPPuttttt0iiii-0-","memw(Rx++#s4:2:circ(Mu) )=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101000000-----PP--------------","barrier"));
	v_ins_st.push_back(Get_Ins_Raw("10101000010-----PP--------------","syncht"));
	v_ins_st.push_back(Get_Ins_Raw("10101011110xxxxxPP0ttttt0iiii---","memd(Rx++#s4:3)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011110xxxxxPP1ttttt-iiii0vv","if (Pv) memd(Rx++#s4:3)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011110xxxxxPP1ttttt-iiii1vv","if (!Pv) memd(Rx++#s4:3)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011000xxxxxPP0ttttt0iiii---","memb(Rx++#s4:0)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011000xxxxxPP1ttttt-iiii0vv","if (Pv) memb(Rx++#s4:0)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011000xxxxxPP1ttttt-iiii1vv","if (!Pv) memb(Rx++#s4:0)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011010xxxxxPP0ttttt0iiii---","memh(Rx++#s4:1)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011011xxxxxPP0ttttt0iiii---","memh(Rx++#s4:1)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101011010xxxxxPP1ttttt-iiii0vv","if (Pv) memh(Rx++#s4:1)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011010xxxxxPP1ttttt-iiii1vv","if (!Pv) memh(Rx++#s4:1)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011011xxxxxPP1ttttt-iiii0vv","if (Pv) memh(Rx++#s4:1)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101011011xxxxxPP1ttttt-iiii1vv","if (!Pv) memh(Rx++#s4:1)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101011100xxxxxPP0ttttt0iiii---","memw(Rx++#s4:2)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011100xxxxxPP1ttttt-iiii0vv","if (Pv) memw(Rx++#s4:2)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101011100xxxxxPP1ttttt-iiii1vv","if (!Pv) memw(Rx++#s4:2)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101101110xxxxxPPuttttt0-------","memd(Rx++Mu)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101101000xxxxxPPuttttt0-------","memb(Rx++Mu)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101101010xxxxxPPuttttt0-------","memh(Rx++Mu)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101101011xxxxxPPuttttt0-------","memh(Rx++Mu)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101101100xxxxxPPuttttt0-------","memw(Rx++Mu)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101111110xxxxxPPuttttt0-------","memd(Rx++Mu:brev)=Rtt"));
	v_ins_st.push_back(Get_Ins_Raw("10101111000xxxxxPPuttttt0-------","memb(Rx++Mu:brev)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101111010xxxxxPPuttttt0-------","memh(Rx++Mu:brev)=Rt"));
	v_ins_st.push_back(Get_Ins_Raw("10101111011xxxxxPPuttttt0-------","memh(Rx++Mu:brev)=Rt.H"));
	v_ins_st.push_back(Get_Ins_Raw("10101111100xxxxxPPuttttt0-------","memw(Rx++Mu:brev)=Rt"));
	v_ins_alu32.push_back(Get_Ins_Raw("1011iiiiiiisssssPPiiiiiiiiiddddd","Rd=add(Rs,#s16)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000010--sssssPP-ttttt00-ddddd","Rdd=extractu(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000011--sssssPP-ttttt11-ddddd","Rdd=lfs(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000000--sssssPP-tttttiiiddddd","Rdd=valignb(Rtt,Rss,#u3)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000010--sssssPP-ttttt01-ddddd","Rdd=shuffeb(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000010--sssssPP-ttttt10-ddddd","Rdd=shuffob(Rtt,Rss)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000010--sssssPP-ttttt11-ddddd","Rdd=shuffeh(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000011--sssssPP-ttttt00-ddddd","Rdd=shuffoh(Rtt,Rss)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000001--sssssPP-tttttiiiddddd","Rdd=vspliceb(Rss,Rtt,#u3)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000011--sssssPP-ttttt01-ddddd","Rdd=vtrunewh(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000011--sssssPP-ttttt10-ddddd","Rdd=vtrunowh(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001111-sssssPP-ttttt00-ddddd","Rdd=vcrotate(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000100--sssssPP-ttttt-uuddddd","Rdd=valignb(Rtt,Rss,Pu)"));
	v_ins_xts2.push_back(Get_Ins_Raw("110000101--sssssPP-ttttt-uuddddd","Rdd=vspliceb(Rss,Rtt,Pu)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001110-sssssPP-ttttt00-ddddd","Rdd=asr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001110-sssssPP-ttttt01-ddddd","Rdd=lsr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001110-sssssPP-ttttt10-ddddd","Rdd=asl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001110-sssssPP-ttttt11-ddddd","Rdd=lsl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001101-sssssPP-ttttt00-ddddd","Rdd=vasrh(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001101-sssssPP-ttttt01-ddddd","Rdd=vlsrh(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001101-sssssPP-ttttt10-ddddd","Rdd=vaslh(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001101-sssssPP-ttttt11-ddddd","Rdd=vlslh(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001100-sssssPP-ttttt00-ddddd","Rdd=vasrw(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001100-sssssPP-ttttt01-ddddd","Rdd=vlsrw(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001100-sssssPP-ttttt10-ddddd","Rdd=vaslw(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100001100-sssssPP-ttttt11-ddddd","Rdd=vlslw(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("11000100---sssssPP-tttttiiiddddd","Rd=addasl(Rt,Rs,#u3)"));
	v_ins_xts2.push_back(Get_Ins_Raw("11000101---sssssPP-ttttt01-ddddd","Rd=vasrw(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011101-sssssPP-ttttt------dd","Pd=bitsset(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011110-sssssPP-ttttt------dd","Pd=bitsclr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011010-sssssPP-ttttt00-ddddd","Rd=setbit(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011010-sssssPP-ttttt01-ddddd","Rd=clrbit(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011010-sssssPP-ttttt10-ddddd","Rd=togglebit(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011100-sssssPP-ttttt------dd","Pd=tstbit(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011001-sssssPP-ttttt00-ddddd","Rd=asr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011001-sssssPP-ttttt01-ddddd","Rd=lsr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011001-sssssPP-ttttt10-ddddd","Rd=asl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011001-sssssPP-ttttt11-ddddd","Rd=lsl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011000-sssssPP-ttttt00-ddddd","Rd=asr(Rs,Rt):sat"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100011000-sssssPP-ttttt10-ddddd","Rd=asl(Rs,Rt):sat"));
	v_ins_xts2.push_back(Get_Ins_Raw("11001001---sssssPP-ttttt---ddddd","Rd=extractu(Rs,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("11001000---sssssPP-ttttt---xxxxx","Rx=insert(Rs,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("11001010---sssssPP-ttttt---xxxxx","Rxx=insert(Rss,Rtt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101110-sssssPP-ttttt00-xxxxx","Rxx-=asr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101110-sssssPP-ttttt01-xxxxx","Rxx-=lsr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101110-sssssPP-ttttt10-xxxxx","Rxx-=asl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101110-sssssPP-ttttt11-xxxxx","Rxx-=lsl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101111-sssssPP-ttttt00-xxxxx","Rxx+=asr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101111-sssssPP-ttttt01-xxxxx","Rxx+=lsr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101111-sssssPP-ttttt10-xxxxx","Rxx+=asl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101111-sssssPP-ttttt11-xxxxx","Rxx+=lsl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101100-sssssPP-ttttt00-xxxxx","Rxx|=asr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101100-sssssPP-ttttt01-xxxxx","Rxx|=lsr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101100-sssssPP-ttttt10-xxxxx","Rxx|=asl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101100-sssssPP-ttttt11-xxxxx","Rxx|=lsl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101101-sssssPP-ttttt00-xxxxx","Rxx&=asr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101101-sssssPP-ttttt01-xxxxx","Rxx&=lsr(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101101-sssssPP-ttttt10-xxxxx","Rxx&=asl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100101101-sssssPP-ttttt11-xxxxx","Rxx&=lsl(Rss,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110010-sssssPP-ttttt00-xxxxx","Rx-=asr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110010-sssssPP-ttttt01-xxxxx","Rx-=lsr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110010-sssssPP-ttttt10-xxxxx","Rx-=asl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110010-sssssPP-ttttt11-xxxxx","Rx-=lsl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110011-sssssPP-ttttt00-xxxxx","Rx+=asr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110011-sssssPP-ttttt01-xxxxx","Rx+=lsr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110011-sssssPP-ttttt10-xxxxx","Rx+=asl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110011-sssssPP-ttttt11-xxxxx","Rx+=lsl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110000-sssssPP-ttttt00-xxxxx","Rx|=asr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110000-sssssPP-ttttt01-xxxxx","Rx|=lsr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110000-sssssPP-ttttt10-xxxxx","Rx|=asl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110000-sssssPP-ttttt11-xxxxx","Rx|=lsl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110001-sssssPP-ttttt00-xxxxx","Rx&=asr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110001-sssssPP-ttttt01-xxxxx","Rx&=lsr(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110001-sssssPP-ttttt10-xxxxx","Rx&=asl(Rs,Rt)"));
	v_ins_xts2.push_back(Get_Ins_Raw("1100110001-sssssPP-ttttt11-xxxxx","Rx&=lsl(Rs,Rt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-000---sssssPP-ttttt---ddddd","Rd=parity(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-001---sssssPP-ttttt-uuddddd","Rdd=vmux(Pu,Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt111ddddd","Rdd=add(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0101--sssssPP-ttttt00----dd","Pd=cmp.eq(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0101--sssssPP-ttttt01----dd","Pd=cmp.gt(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0101--sssssPP-ttttt10----dd","Pd=cmp.gtu(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011111sssssPP-ttttt00-ddddd","Rdd=and(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011111sssssPP-ttttt01-ddddd","Rdd=or(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011111sssssPP-ttttt10-ddddd","Rdd=xor(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt111ddddd","Rdd=sub(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt000ddddd","Rdd=vaddub(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt001ddddd","Rdd=vaddub(Rss,Rtt):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt000ddddd","Rdd=vavgub(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt001ddddd","Rdd=vavgub(Rss,Rtt):rnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt110---dd","Pd=vcmpb.eq(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt111---dd","Pd=vcmpb.gtu(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011110sssssPP-ttttt000ddddd","Rdd=vmaxub(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt000ddddd","Rdd=vminub(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt000ddddd","Rdd=vsubub(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt001ddddd","Rdd=vsubub(Rtt,Rss):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt010ddddd","Rdd=vaddh(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt011ddddd","Rdd=vaddh(Rss,Rtt):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt100ddddd","Rdd=vadduh(Rss,Rtt):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt010ddddd","Rdd=vavgh(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt011ddddd","Rdd=vavgh(Rss,Rtt):rnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt100ddddd","Rdd=vavgh(Rss,Rtt):crnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt101ddddd","Rdd=vavguh(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011010sssssPP-ttttt11-ddddd","Rdd=vavguh(Rss,Rtt):rnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt000ddddd","Rdd=vnavgh(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt001ddddd","Rdd=vnavgh(Rtt,Rss):rnd:sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt010ddddd","Rdd=vnavgh(Rtt,Rss):crnd:sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt011---dd","Pd=vcmph.eq(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt100---dd","Pd=vcmph.gt(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt101---dd","Pd=vcmph.gtu(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011110sssssPP-ttttt001ddddd","Rdd=vmaxh(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011110sssssPP-ttttt010ddddd","Rdd=vmaxuh(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt001ddddd","Rdd=vminh(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt010ddddd","Rdd=vminuh(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt010ddddd","Rdd=vsubh(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt011ddddd","Rdd=vsubh(Rtt,Rss):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt100ddddd","Rdd=vsubuh(Rtt,Rss):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt101ddddd","Rdd=vaddw(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011000sssssPP-ttttt110ddddd","Rdd=vaddw(Rss,Rtt):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011011sssssPP-ttttt000ddddd","Rdd=vavgw(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011011sssssPP-ttttt001ddddd","Rdd=vavgw(Rss,Rtt):rnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011011sssssPP-ttttt010ddddd","Rdd=vavgw(Rss,Rtt):crnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011011sssssPP-ttttt011ddddd","Rdd=vavguw(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011011sssssPP-ttttt1--ddddd","Rdd=vavguw(Rss,Rtt):rnd"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt011ddddd","Rdd=vnavgw(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt10-ddddd","Rdd=vnavgw(Rtt,Rss):rnd:sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011100sssssPP-ttttt11-ddddd","Rdd=vnavgw(Rtt,Rss):crnd:sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt000---dd","Pd=vcmpw.eq(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt001---dd","Pd=vcmpw.gt(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-0100--sssssPP-ttttt010---dd","Pd=vcmpw.gtu(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt101ddddd","Rdd=vmaxuw(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011110sssssPP-ttttt011ddddd","Rdd=vmaxw(Rss,Rtt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt011ddddd","Rdd=vminw(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011101sssssPP-ttttt100ddddd","Rdd=vminuw(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt101ddddd","Rdd=vsubw(Rtt,Rss)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-011001sssssPP-ttttt110ddddd","Rdd=vsubw(Rtt,Rss):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101100sssssPP-ttttt0--ddddd","Rd=add(Rs,Rt):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101000sssssPP-ttttt00-ddddd","Rd=add(Rt.L,Rs.L)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101000sssssPP-ttttt01-ddddd","Rd=add(Rt.L,Rs.H)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101000sssssPP-ttttt10-ddddd","Rd=add(Rt.L,Rs.L):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101000sssssPP-ttttt11-ddddd","Rd=add(Rt.L,Rs.H):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt000ddddd","Rd=add(Rt.L,Rs.L):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt001ddddd","Rd=add(Rt.L,Rs.H):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt010ddddd","Rd=add(Rt.H,Rs.L):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt011ddddd","Rd=add(Rt.H,Rs.H):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt100ddddd","Rd=add(Rt.L,Rs.L):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt101ddddd","Rd=add(Rt.L,Rs.H):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt110ddddd","Rd=add(Rt.H,Rs.L):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101010sssssPP-ttttt111ddddd","Rd=add(Rt.H,Rs.H):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101110sssssPP-ttttt0--ddddd","Rd=max(Rs,Rt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101110sssssPP-ttttt1--ddddd","Rd=maxu(Rs,Rt)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101101sssssPP-ttttt0--ddddd","Rd=min(Rt,Rs)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101101sssssPP-ttttt1--ddddd","Rd=minu(Rt,Rs)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101100sssssPP-ttttt1--ddddd","Rd=sub(Rt,Rs):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101001sssssPP-ttttt00-ddddd","Rd=sub(Rt.L,Rs.L)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101001sssssPP-ttttt01-ddddd","Rd=sub(Rt.L,Rs.H)"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101001sssssPP-ttttt10-ddddd","Rd=sub(Rt.L,Rs.L):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101001sssssPP-ttttt11-ddddd","Rd=sub(Rt.L,Rs.H):sat"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt000ddddd","Rd=sub(Rt.L,Rs.L):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt001ddddd","Rd=sub(Rt.L,Rs.H):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt010ddddd","Rd=sub(Rt.H,Rs.L):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt011ddddd","Rd=sub(Rt.H,Rs.H):<<16"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt100ddddd","Rd=sub(Rt.L,Rs.L):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt101ddddd","Rd=sub(Rt.L,Rs.H):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt110ddddd","Rd=sub(Rt.H,Rs.L):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-101011sssssPP-ttttt111ddddd","Rd=sub(Rt.H,Rs.H):sat:<<1 6"));
	v_ins_xt64.push_back(Get_Ins_Raw("1101-100---sssssPP-ttttt---ddddd","Rdd=packhl(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000000--sssssPP-iiiiiiiiddddd","Rd=+mpyi(Rs,#u8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000001--sssssPP-iiiiiiiiddddd","Rd=-mpyi(Rs,#u8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000010--sssssPP-iiiiiiiixxxxx","Rx+=mpyi(Rs,#u8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000011--sssssPP-iiiiiiiixxxxx","Rx-=mpyi(Rs,#u8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000100--sssssPP-iiiiiiiixxxxx","Rx+=add(Rs,#s8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111000101--sssssPP-iiiiiiiixxxxx","Rx-=add(Rs,#s8)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101N00sssssPP-ttttt110ddddd","Rdd=cmpy(Rs,Rt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101N10sssssPP-ttttt110ddddd","Rdd=cmpy(Rs,Rt*)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101000sssssPP-ttttt001ddddd","Rdd=cmpyi(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101000sssssPP-ttttt010ddddd","Rdd=cmpyr(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101000sssssPP-ttttt000ddddd","Rdd=mpy(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101010sssssPP-ttttt000ddddd","Rdd=mpyu(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N00sssssPP-ttttt-00ddddd","Rdd=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N00sssssPP-ttttt-01ddddd","Rdd=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N00sssssPP-ttttt-10ddddd","Rdd=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N00sssssPP-ttttt-11ddddd","Rdd=mpy(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N01sssssPP-ttttt-00ddddd","Rdd=mpy(Rs.L,Rt.L)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N01sssssPP-ttttt-01ddddd","Rdd=mpy(Rs.L,Rt.H)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N01sssssPP-ttttt-10ddddd","Rdd=mpy(Rs.H,Rt.L)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N01sssssPP-ttttt-11ddddd","Rdd=mpy(Rs.H,Rt.H)[:<<N] :rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N10sssssPP-ttttt-00ddddd","Rdd=mpyu(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N10sssssPP-ttttt-01ddddd","Rdd=mpyu(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N10sssssPP-ttttt-10ddddd","Rdd=mpyu(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100100N10sssssPP-ttttt-11ddddd","Rdd=mpyu(Rs.H,Rt.H)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100101N00sssssPP-ttttt101ddddd","Rdd=vmpyh(Rs,Rt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111N00sssssPP-ttttt110xxxxx","Rxx+=cmpy(Rs,Rt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111N00sssssPP-ttttt111xxxxx","Rxx-=cmpy(Rs,Rt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111N10sssssPP-ttttt110xxxxx","Rxx+=cmpy(Rs,Rt*)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111N10sssssPP-ttttt111xxxxx","Rxx-=cmpy(Rs,Rt*)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111000sssssPP-ttttt001xxxxx","Rxx+=cmpyi(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111000sssssPP-ttttt010xxxxx","Rxx+=cmpyr(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111000sssssPP-ttttt000xxxxx","Rxx+=mpy(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111001sssssPP-ttttt000xxxxx","Rxx-=mpy(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111010sssssPP-ttttt000xxxxx","Rxx+=mpyu(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111011sssssPP-ttttt000xxxxx","Rxx-=mpyu(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N00sssssPP-ttttt-00xxxxx","Rxx+=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N00sssssPP-ttttt-01xxxxx","Rxx+=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N00sssssPP-ttttt-10xxxxx","Rxx+=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N00sssssPP-ttttt-11xxxxx","Rxx+=mpy(Rs.H,Rt.H)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N01sssssPP-ttttt-00xxxxx","Rxx-=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N01sssssPP-ttttt-01xxxxx","Rxx-=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N01sssssPP-ttttt-10xxxxx","Rxx-=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N01sssssPP-ttttt-11xxxxx","Rxx-=mpy(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N10sssssPP-ttttt-00xxxxx","Rxx+=mpyu(Rs.L,Rt.L)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N10sssssPP-ttttt-01xxxxx","Rxx+=mpyu(Rs.L,Rt.H)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N10sssssPP-ttttt-10xxxxx","Rxx+=mpyu(Rs.H,Rt.L)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N10sssssPP-ttttt-11xxxxx","Rxx+=mpyu(Rs.H,Rt.H)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N11sssssPP-ttttt-00xxxxx","Rxx-=mpyu(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N11sssssPP-ttttt-01xxxxx","Rxx-=mpyu(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N11sssssPP-ttttt-10xxxxx","Rxx-=mpyu(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100110N11sssssPP-ttttt-11xxxxx","Rxx-=mpyu(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111001sssssPP-ttttt001xxxxx","Rxx+=vmpyh(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11100111N00sssssPP-ttttt101xxxxx","Rxx+=vmpyh(Rs,Rt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000001sssssPP-ttttt000ddddd","Rdd=vabsdiffw(Rtt,Rss)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000011sssssPP-ttttt000ddddd","Rdd=vabsdiffh(Rtt,Rss)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N01sssssPP-ttttt110ddddd","Rdd=vcmpyr(Rss,Rtt)[:<<N] :sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N10sssssPP-ttttt110ddddd","Rdd=vcmpyi(Rss,Rtt)[:<<N] :sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000000sssssPP-ttttt000ddddd","Rdd=vrcmpyi(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000000sssssPP-ttttt001ddddd","Rdd=vrcmpyr(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000010sssssPP-ttttt000ddddd","Rdd=vrcmpyi(Rss,Rtt*)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000011sssssPP-ttttt001ddddd","Rdd=vrcmpyr(Rss,Rtt*)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N00sssssPP-ttttt101ddddd","Rdd=vmpyweh(Rss,Rtt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N00sssssPP-ttttt111ddddd","Rdd=vmpywoh(Rss,Rtt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N01sssssPP-ttttt101ddddd","Rdd=vmpyweh(Rss,Rtt)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N01sssssPP-ttttt111ddddd","Rdd=vmpywoh(Rss,Rtt)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N10sssssPP-ttttt101ddddd","Rdd=vmpyweuh(Rss,Rtt)[:< <N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N10sssssPP-ttttt111ddddd","Rdd=vmpywouh(Rss,Rtt)[:< <N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N11sssssPP-ttttt101ddddd","Rdd=vmpyweuh(Rss,Rtt)[:< <N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N11sssssPP-ttttt111ddddd","Rdd=vmpywouh(Rss,Rtt)[:< <N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000010sssssPP-ttttt001ddddd","Rdd=vraddub(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000010sssssPP-ttttt010ddddd","Rdd=vrsadub(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N00sssssPP-ttttt100ddddd","Rdd=vdmpy(Rss,Rtt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101001N--sssssPP-ttttt-00ddddd","Rd=vdmpy(Rss,Rtt)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000N00sssssPP-ttttt110ddddd","Rdd=vmpyeh(Rss,Rtt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101000000sssssPP-ttttt010ddddd","Rdd=vrmpyh(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010001sssssPP-ttttt100xxxxx","Rxx+=vcmpyr(Rss,Rtt):sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010010sssssPP-ttttt100xxxxx","Rxx+=vcmpyi(Rss,Rtt):sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010000sssssPP-ttttt000xxxxx","Rxx+=vrcmpyi(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010000sssssPP-ttttt001xxxxx","Rxx+=vrcmpyr(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010010sssssPP-ttttt000xxxxx","Rxx+=vrcmpyi(Rss,Rtt*)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010011sssssPP-ttttt001xxxxx","Rxx+=vrcmpyr(Rss,Rtt*)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N00sssssPP-ttttt101xxxxx","Rxx+=vmpyweh(Rss,Rtt)[:< <N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N00sssssPP-ttttt111xxxxx","Rxx+=vmpywoh(Rss,Rtt)[:< <N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N01sssssPP-ttttt101xxxxx","Rxx+=vmpyweh(Rss,Rtt)[:< <N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N01sssssPP-ttttt111xxxxx","Rxx+=vmpywoh(Rss,Rtt)[:< <N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N10sssssPP-ttttt101xxxxx","Rxx+=vmpyweuh(Rss,Rtt)[: <<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N10sssssPP-ttttt111xxxxx","Rxx+=vmpywouh(Rss,Rtt)[: <<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N11sssssPP-ttttt101xxxxx","Rxx+=vmpyweuh(Rss,Rtt)[: <<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N11sssssPP-ttttt111xxxxx","Rxx+=vmpywouh(Rss,Rtt)[: <<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010010sssssPP-ttttt001xxxxx","Rxx+=vraddub(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010010sssssPP-ttttt010xxxxx","Rxx+=vrsadub(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N00sssssPP-ttttt100xxxxx","Rxx+=vdmpy(Rss,Rtt)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010001sssssPP-ttttt010xxxxx","Rxx+=vmpyeh(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010N00sssssPP-ttttt110xxxxx","Rxx+=vmpyeh(Rss,Rtt)[:<< N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101010000sssssPP-ttttt010xxxxx","Rxx+=vrmpyh(Rss,Rtt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101N01sssssPP-ttttt110ddddd","Rd=cmpy(Rs,Rt)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101N11sssssPP-ttttt110ddddd","Rd=cmpy(Rs,Rt*)[:<<N]:rnd :sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101000sssssPP-ttttt000ddddd","Rd=mpyi(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101000sssssPP-ttttt001ddddd","Rd=mpy(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101001sssssPP-ttttt001ddddd","Rd=mpy(Rs,Rt):rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101010sssssPP-ttttt001ddddd","Rd=mpyu(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101101sssssPP-ttttt100ddddd","Rd=mpy(Rs,Rt.H):<<1:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101111sssssPP-ttttt100ddddd","Rd=mpy(Rs,Rt.L):<<1:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt000ddddd","Rd=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt001ddddd","Rd=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt010ddddd","Rd=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt011ddddd","Rd=mpy(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt100ddddd","Rd=mpy(Rs.L,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt101ddddd","Rd=mpy(Rs.L,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt110ddddd","Rd=mpy(Rs.H,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N00sssssPP-ttttt111ddddd","Rd=mpy(Rs.H,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt000ddddd","Rd=mpy(Rs.L,Rt.L)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt001ddddd","Rd=mpy(Rs.L,Rt.H)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt010ddddd","Rd=mpy(Rs.H,Rt.L)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt011ddddd","Rd=mpy(Rs.H,Rt.H)[:<<N]:rnd"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt100ddddd","Rd=mpy(Rs.L,Rt.L)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt101ddddd","Rd=mpy(Rs.L,Rt.H)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt110ddddd","Rd=mpy(Rs.H,Rt.L)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N01sssssPP-ttttt111ddddd","Rd=mpy(Rs.H,Rt.H)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N10sssssPP-ttttt000ddddd","Rd=mpyu(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N10sssssPP-ttttt001ddddd","Rd=mpyu(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N10sssssPP-ttttt010ddddd","Rd=mpyu(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101100N10sssssPP-ttttt011ddddd","Rd=mpyu(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101101N01sssssPP-ttttt111ddddd","Rd=vmpyh(Rs,Rt)[:<<N]:rnd:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("111011110--sssssPP-ttttt-01xxxxx","Rx+=add(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111011111--sssssPP-ttttt-01xxxxx","Rx-=add(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111011110--sssssPP-ttttt-11xxxxx","Rx+=sub(Rt,Rs)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111011111--sssssPP-ttttt-11xxxxx","Rx^=xor(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("111011110--sssssPP-ttttt-00xxxxx","Rx+=mpyi(Rs,Rt)"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt000xxxxx","Rx+=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt001xxxxx","Rx+=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt010xxxxx","Rx+=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt011xxxxx","Rx+=mpy(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt100xxxxx","Rx+=mpy(Rs.L,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt101xxxxx","Rx+=mpy(Rs.L,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt110xxxxx","Rx+=mpy(Rs.H,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N00sssssPP-ttttt111xxxxx","Rx+=mpy(Rs.H,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt000xxxxx","Rx-=mpy(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt001xxxxx","Rx-=mpy(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt010xxxxx","Rx-=mpy(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt011xxxxx","Rx-=mpy(Rs.H,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt100xxxxx","Rx-=mpy(Rs.L,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt101xxxxx","Rx-=mpy(Rs.L,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt110xxxxx","Rx-=mpy(Rs.H,Rt.L)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N01sssssPP-ttttt111xxxxx","Rx-=mpy(Rs.H,Rt.H)[:<<N]:sat"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N10sssssPP-ttttt000xxxxx","Rx+=mpyu(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N10sssssPP-ttttt001xxxxx","Rx+=mpyu(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N10sssssPP-ttttt010xxxxx","Rx+=mpyu(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N10sssssPP-ttttt011xxxxx","Rx+=mpyu(Rs.H,Rt.H)[:<< N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N11sssssPP-ttttt000xxxxx","Rx-=mpyu(Rs.L,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N11sssssPP-ttttt001xxxxx","Rx-=mpyu(Rs.L,Rt.H)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N11sssssPP-ttttt010xxxxx","Rx-=mpyu(Rs.H,Rt.L)[:<<N]"));
	v_ins_xtm.push_back(Get_Ins_Raw("11101110N11sssssPP-ttttt011xxxxx","Rx-=mpyu(Rs.H,Rt.H)[:<<N]"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110001-00sssssPP-ttttt---ddddd","Rd=and(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110001-01sssssPP-ttttt---ddddd","Rd=or(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110001-11sssssPP-ttttt---ddddd","Rd=xor(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111100110-0sssssPP-ttttt---ddddd","Rd=add(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111100110-1sssssPP-ttttt---ddddd","Rd=sub(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110011100sssssPP-ttttt---ddddd","R=combine(Rt.H,Rs.H)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110011101sssssPP-ttttt---ddddd","Rd=combine(Rt.H,Rs.L)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110011110sssssPP-ttttt---ddddd","Rd=combine(Rt.L,Rs.H)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110011111sssssPP-ttttt---ddddd","Rd=combine(Rt.L,Rs.L)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110010-00sssssPP-ttttt------dd","Pd=cmp.eq(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110010-10sssssPP-ttttt------dd","Pd=cmp.gt(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110010-11sssssPP-ttttt------dd","Pd=cmp.gtu(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110101---sssssPP-ttttt---ddddd","Rdd=combine(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110100---sssssPP-ttttt-uuddddd","Rd=mux(Pu,Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110000sssssPP-ttttt---ddddd","Rd=vaddh(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110001sssssPP-ttttt---ddddd","Rd=vaddh(Rs,Rt):sat"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110011sssssPP-ttttt---ddddd","Rd=vadduh(Rs,Rt):sat"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110111-00sssssPP-ttttt---ddddd","Rd=vavgh(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110111-01sssssPP-ttttt---ddddd","Rd=vavgh(Rs,Rt):rnd"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110111-11sssssPP-ttttt---ddddd","Rd=vnavgh(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110100sssssPP-ttttt---ddddd","Rd=vsubh(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110101sssssPP-ttttt---ddddd","Rd=vsubh(Rt,Rs):sat"));
	v_ins_a3215.push_back(Get_Ins_Raw("11110110111sssssPP-ttttt---ddddd","Rd=vsubuh(Rt,Rs):sat"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-00sssssPP0ttttt0uuddddd","if (Pu) Rd=and(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-00sssssPP0ttttt1uuddddd","if (!Pu) Rd=and(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-00sssssPP1ttttt0uuddddd","if (Pu.new) Rd=and(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-00sssssPP1ttttt1uuddddd","if (!Pu.new) Rd=and(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-01sssssPP0ttttt0uuddddd","if (Pu) Rd=or(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-01sssssPP0ttttt1uuddddd","if (!Pu) Rd=or(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-01sssssPP1ttttt0uuddddd","if (Pu.new) Rd=or(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-01sssssPP1ttttt1uuddddd","if (!Pu.new) Rd=or(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-11sssssPP0ttttt0uuddddd","if (Pu) Rd=xor(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-11sssssPP0ttttt1uuddddd","if (!Pu) Rd=xor(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-11sssssPP1ttttt0uuddddd","if (Pu.new) Rd=xor(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111001-11sssssPP1ttttt1uuddddd","if (!Pu.new) Rd=xor(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-0sssssPP0ttttt0uuddddd","if (Pu) Rd=add(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-0sssssPP0ttttt1uuddddd","if (!Pu) Rd=add(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-0sssssPP1ttttt0uuddddd","if (Pu.new) Rd=add(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-0sssssPP1ttttt1uuddddd","if (!Pu.new) Rd=add(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-1sssssPP0ttttt0uuddddd","if (Pu) Rd=sub(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-1sssssPP0ttttt1uuddddd","if (!Pu) Rd=sub(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-1sssssPP1ttttt0uuddddd","if (Pu.new) Rd=sub(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("111110110-1sssssPP1ttttt1uuddddd","if (!Pu.new) Rd=sub(Rt,Rs)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111101---sssssPP0ttttt0uuddddd","if (Pu) Rdd=combine(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111101---sssssPP0ttttt1uuddddd","if (!Pu) Rdd=combine(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111101---sssssPP1ttttt0uuddddd","if (Pu.new) Rdd=combine(Rs,Rt)"));
	v_ins_a3215.push_back(Get_Ins_Raw("11111101---sssssPP1ttttt1uuddddd","if (!Pu.new) Rdd=combine(Rs,Rt)"));
}

