-Ritual de inicio de sesión
Pega algo así:
Hola OpenCode. Antes de tocar código:
1. Lee Memory.md y todo.md.
2. Ejecuta `git status --short` y revisa la estructura de core/ y adapters/.
3. Resume el estado actual, el próximo paso y los riesgos.
No modifiques nada hasta que te confirme el plan.
Y si la tarea toca la matriz o la arquitectura, añade:
Lee también Contex.md y Skill.md para respetar el orden 3-21 y los patrones del proyecto.
Ritual de cierre de sesión
Para no empezar desde cero, lo importante es cerrar bien:
1. Actualizar Memory.md con:
- Estado actual.
- Decisiones tomadas.
- Qué se probó y con qué comandos.
- Bloqueos o riesgos.
- Próximos 3 pasos concretos.
2. Actualizar todo.md marcando [x] lo completado.
3. Hacer commit de los cambios. Aunque sea un commit pequeño, evita depender de la memoria del chat.
4. Dejar las pruebas en tests/, no en una carpeta temporal, para que la próxima sesión pueda ejecutarlas.