# seccomp_config.py
import logging
import errno

try:
    import seccomp
except ImportError:
    logging.error("La bibliothèque 'seccomp' n'est pas installée. Le filtre ne sera pas appliqué.")
    logging.error("Installez-la avec : pip install seccomp")
    seccomp = None

def apply_seccomp_blacklist():
    """
    Applique un filtre seccomp (blacklist) pour bloquer les appels système
    les plus dangereux (exec, fork, etc.) afin de limiter les dégâts
    en cas de RCE.
    """
    if not seccomp:
        logging.warning("Module seccomp non disponible. Le sandboxing des syscalls est désactivé.")
        return

    try:
        # Liste des syscalls à bloquer.
        # On bloque l'exécution de commandes, la création de processus,
        # et les changements de privilèges.
        blacklist = [
            'execve', 'execveat',
            'fork', 'vfork', 'clone',
            'setuid', 'setgid', 'setreuid', 'setregid',
            'kill', 'ptrace', 'bpf', 'mount', 'reboot'
        ]

        # On autorise tout par défaut (defaction=ALLOW)
        # et on bloque spécifiquement la blacklist.
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)

        for syscall_name in blacklist:
            try:
                # On retourne une erreur "Operation Not Permitted"
                # si l'un de ces appels est tenté.
                f.add_rule(seccomp.ERRNO(errno.EPERM), syscall_name)
            except seccomp.SyscallFilterError:
                # Ignorer si le syscall n'existe pas sur cette architecture
                logging.debug(f"Impossible d'ajouter la règle seccomp pour: {syscall_name}")

        f.load()
        logging.info("Filtre seccomp (blacklist) chargé avec succès. Les syscalls dangereux sont bloqués.")

    except Exception as e:
        logging.error(f"Erreur critique lors de l'application du filtre seccomp: {e}")
        # En production, vous pourriez vouloir quitter si le filtre échoue
        # exit(1)
