/**
  ******************************************************************************
  * @file    main.c
  * @author  fire
  * @version V1.0
  * @date    2013-xx-xx
  * @brief   ���Է�����
  ******************************************************************************
  * @attention
  *	 
  * ʵ��ƽ̨:Ұ�� �Ե� STM32 ������ 
  * ��̳    :http://www.firebbs.cn
  * �Ա�    :http://fire-stm32.taobao.com  *
  ******************************************************************************
  */ 
	
#include "stm32f10x.h"
#include "app_rsa.h"
#include "bsp_usart.h"


float temperature;
/**
  * @brief  ������
  * @param  ��
  * @retval ��
  */
  
#include<stdlib.h>
  
/****************************************************************************** 
* ��������DRV_InterGenerateRandVec(ԭ random_vector_generate)
* �� �ܣ��������ֵ
* �� �룺uint8_t size
* �� ����uint8_t *p_buff
* �� �أ�uint8_t
*/
uint8_t DRV_InterGenerateRandVec(uint8_t *p_buff, uint8_t size)
{
	uint8_t length = 0;
	while (size --)
	{
		*p_buff = (uint8_t)(rand()&0xFF);
		p_buff++;
		length++;
	}
    return length;
}
uint8_t PUBLIC_GenerateRandVec(uint8_t *p_buff, uint8_t size)
{
    return DRV_InterGenerateRandVec(p_buff, size);
}
void Delay(__IO u32 nCount); 
/**
  * @brief  ������
  * @param  ��  
  * @retval ��
  */

int main(void)
{	
	/* BEEP GPIO ��ʼ�� */
	// BEEP_GPIO_Config();	
	Serial_Init();
	RSA_TEST();
	
	while(1)
	{		
	}
}

void Delay(__IO uint32_t nCount)	 //�򵥵���ʱ����
{
	for(; nCount != 0; nCount--);
}



/*********************************************END OF FILE**********************/
