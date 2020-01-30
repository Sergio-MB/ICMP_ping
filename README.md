# ICMP_ping
 Servicio de ping escrito en C usando el protocolo ICMP. Proyecto desarrollado con fines de aprendizaje en Arquitectura de Redes y Servicios de la asignatura de Ingeniería de Software de la Universidad de Valladolid.
 
## Content

- [Descripción del programa](ICMP_ping_Description.pdf) - Requisitos de desarrollo
- [miping-Munumer-Blazquez.c](miping-Munumer-Blazquez.c) -  Implementación Ping ICMP.

## Development

### Requirements

- [GCC](https://gcc.gnu.org), the GNU Compiler Collection.

### Installation

```bash
# Clone repository.
git clone https://github.com/Sergio-MB/ICMP_ping.git
cd ICMP_ping
```

### Compilation

```bash
gcc -Wall -o miping.out miping-Munumer-Blazquez.c
```

### Execution

```bash
./miping.out ip-address [-v]
```

## Deployment

### Remote Linux Virtual Machine via SSH

This C program should be executed in a provided Slackware Linux machine, so one option to send the source files to there is:

```bash
# Transfer file to remote machine
scp -P <port-number> miping-Munumer-Blazquez.c youruser@your.machine.address:/destination/folder
```

Then, you can access to your remote machine via SSH and execute it there.
