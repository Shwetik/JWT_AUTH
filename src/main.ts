import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module'; // Import the main application module

async function bootstrap() {
  const app = await NestFactory.create(AppModule); // Create the NestJS application
  await app.listen(3021); // Listen on port 3000 or any port you prefer
  console.log(`Application is running on: ${await app.getUrl()}`);
}

bootstrap();