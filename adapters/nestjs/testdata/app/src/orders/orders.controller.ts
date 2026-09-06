import { Controller, Get, Delete, Param, UseGuards } from '@nestjs/common';
import { RequirePermission } from '../common/require-permission.decorator';
import { AuthenticatedOnly } from '../common/authenticated-only.decorator';
import { WeirdCustomGuard } from './weird.guard';

@Controller('orders')
export class OrdersController {
  // AUTHENTICATED + AUTHORIZED. Note the decorator order: the route decorator
  // comes first and the authorization decorator after it.
  @Get(':orderId')
  @RequirePermission('read', 'Order')
  async findById(@Param('orderId') orderId: string): Promise<void> {}

  // AUTHENTICATED, no authorization decorator.
  @Get()
  @AuthenticatedOnly()
  async findAll(): Promise<void> {}

  // AMBIGUOUS: a guard whose semantics this adapter does not recognise. It may
  // well authorize; claiming "absent" would invent the absence of a control.
  @Delete(':orderId')
  @UseGuards(WeirdCustomGuard)
  async remove(@Param('orderId') orderId: string): Promise<void> {}

  // AMBIGUOUS: the path is computed.
  @Get(ROUTE_PATH)
  async dynamic(): Promise<void> {}
}
