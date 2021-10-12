#ifndef NVM_NVM_H_
#define NVM_NVM_H_

void error_trap(void);
void NVM_read(uint8_t *buffer, size_t len);
void NVM_write(uint8_t *buffer, size_t len);

#endif /* NVM_NVM_H_ */