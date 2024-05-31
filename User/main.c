/**
  ******************************************************************************
  * @file    main.c
  * @author  fire
  * @version V1.0
  * @date    2013-xx-xx
  * @brief   测试蜂鸣器
  ******************************************************************************
  * @attention
  *	 
  * 实验平台:野火 霸道 STM32 开发板 
  * 论坛    :http://www.firebbs.cn
  * 淘宝    :http://fire-stm32.taobao.com  *
  ******************************************************************************
  */ 
	
#include "stm32f10x.h"
#include "app_rsa.h"
#include "bsp_usart.h"


float temperature;
/**
  * @brief  主函数
  * @param  无
  * @retval 无
  */
  
#include<stdlib.h>
  
/****************************************************************************** 
* 函数名：DRV_InterGenerateRandVec(原 random_vector_generate)
* 功 能：生成随机值
* 输 入：uint8_t size
* 输 出：uint8_t *p_buff
* 返 回：uint8_t
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
  * @brief  主函数
  * @param  无  
  * @retval 无
  */

int main(void)
{	
	/* BEEP GPIO 初始化 */
	// BEEP_GPIO_Config();	
	Serial_Init();
	RSA_TEST();
	
	while(1)
	{		
	}
}

void Delay(__IO uint32_t nCount)	 //简单的延时函数
{
	for(; nCount != 0; nCount--);
}



/*********************************************END OF FILE**********************/
